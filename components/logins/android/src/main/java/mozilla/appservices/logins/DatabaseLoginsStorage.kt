/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package mozilla.appservices.logins

import com.sun.jna.Pointer
import mozilla.appservices.logins.rust.PasswordSyncAdapter
import mozilla.appservices.logins.rust.RustError
import org.mozilla.appservices.logins.GleanMetrics.LoginsStore as LoginsStoreMetrics
import mozilla.appservices.sync15.SyncTelemetryPing
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONArray

/**
 * LoginsStorage implementation backed by a database.
 */
class DatabaseLoginsStorage(private val dbPath: String) : AutoCloseable, LoginsStorage {
    private var raw: AtomicLong = AtomicLong(0)

    override fun isLocked(): Boolean {
        return raw.get() == 0L
    }

    private fun checkUnlocked(): Long {
        val handle = raw.get()
        if (handle == 0L) {
            throw LoginsStorageException("Using DatabaseLoginsStorage without unlocking first")
        }
        return handle
    }

    /**
     * Return the raw handle used to reference this logins database.
     *
     * Generally should only be used to pass the handle into `SyncManager.setLogins`.
     *
     * Note: handles do not remain valid after locking / unlocking the logins database.
     */
    override fun getHandle(): Long {
        return this.raw.get()
    }

    @Synchronized
    @Throws(LoginsStorageException::class)
    override fun lock() {
        val raw = this.raw.getAndSet(0)
        if (raw == 0L) {
            throw MismatchedLockException("Lock called when we are already locked")
        }
        rustCall { error ->
            PasswordSyncAdapter.INSTANCE.sync15_passwords_state_destroy(raw, error)
        }
    }

    @Synchronized
    @Throws(LoginsStorageException::class)
    override fun unlock(encryptionKey: String) {
        return rustCall {
            if (!isLocked()) {
                throw MismatchedLockException("Unlock called when we are already unlocked")
            }
            LoginsStoreMetrics.unlockCount.add()
            try {
                val timer = LoginsStoreMetrics.unlockTime.start()
                try {
                    raw.set(PasswordSyncAdapter.INSTANCE.sync15_passwords_state_new(
                            dbPath,
                            encryptionKey,
                            it))
                } finally {
                    LoginsStoreMetrics.unlockTime.stopAndAccumulate(timer)
                }
            } catch (e: Exception) {
                LoginsStoreMetrics.unlockErrorCount["some_label"].add()
                throw e
            }
            // XXX TODO: the app might not be happy to have db access right on startup?
            // Probably not an issue for logins, but would love to find a better pattern here...
            gatherSnapshotMetrics()
        }
    }

    @Synchronized
    @Throws(LoginsStorageException::class)
    override fun unlock(encryptionKey: ByteArray) {
        return rustCall {
            if (!isLocked()) {
                throw MismatchedLockException("Unlock called when we are already unlocked")
            }
            LoginsStoreMetrics.unlockCount.add()
            try {
                val timer = LoginsStoreMetrics.unlockTime.start()
                try {
                    raw.set(PasswordSyncAdapter.INSTANCE.sync15_passwords_state_new_with_hex_key(
                            dbPath,
                            encryptionKey,
                            encryptionKey.size,
                            it))
                } finally {
                    LoginsStoreMetrics.unlockTime.stopAndAccumulate(timer)
                }
            } catch (e: Exception) {
                LoginsStoreMetrics.unlockErrorCount["some_label"].add()
                throw e
            }
            gatherSnapshotMetrics()
        }
    }

    @Synchronized
    @Throws(LoginsStorageException::class)
    override fun ensureUnlocked(encryptionKey: String) {
        if (isLocked()) {
            this.unlock(encryptionKey)
        }
    }

    @Synchronized
    @Throws(LoginsStorageException::class)
    override fun ensureUnlocked(encryptionKey: ByteArray) {
        if (isLocked()) {
            this.unlock(encryptionKey)
        }
    }

    @Synchronized
    override fun ensureLocked() {
        if (!isLocked()) {
            this.lock()
        }
    }

    @Throws(LoginsStorageException::class)
    override fun sync(syncInfo: SyncUnlockInfo): SyncTelemetryPing {
        val json = rustCallWithLock { raw, error ->
            PasswordSyncAdapter.INSTANCE.sync15_passwords_sync(
                    raw,
                    syncInfo.kid,
                    syncInfo.fxaAccessToken,
                    syncInfo.syncKey,
                    syncInfo.tokenserverURL,
                    error
            )?.getAndConsumeRustString()
        }
        // XXX TODO: Fenix won't actually call this IIUC, because it uses the
        // SyncManager, which plugs in directly at the Rust level.
        gatherSnapshotMetrics()
        // XXX TODO maybe even insert iti nto the sync ping while we're here?
        // Or should the rust code do that for us?
        return SyncTelemetryPing.fromJSONString(json)
    }

    @Throws(LoginsStorageException::class)
    override fun reset() {
        rustCallWithLock { raw, error ->
            PasswordSyncAdapter.INSTANCE.sync15_passwords_reset(raw, error)
        }
        gatherSnapshotMetrics()
    }

    @Throws(LoginsStorageException::class)
    override fun wipe() {
        rustCallWithLock { raw, error ->
            PasswordSyncAdapter.INSTANCE.sync15_passwords_wipe(raw, error)
        }
        gatherSnapshotMetrics()
    }

    @Throws(LoginsStorageException::class)
    override fun wipeLocal() {
        rustCallWithLock { raw, error ->
            PasswordSyncAdapter.INSTANCE.sync15_passwords_wipe_local(raw, error)
        }
        gatherSnapshotMetrics()
    }

    @Throws(LoginsStorageException::class)
    override fun delete(id: String): Boolean {
        return withQueryMetricsWrite {
            rustCallWithLock { raw, error ->
                val deleted = PasswordSyncAdapter.INSTANCE.sync15_passwords_delete(raw, id, error)
                deleted.toInt() != 0
            }
        }

    }

    @Throws(LoginsStorageException::class)
    override fun get(id: String): ServerPassword? {
        return withQueryMetricsRead {
            val json = nullableRustCallWithLock { raw, error ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_get_by_id(raw, id, error)
            }?.getAndConsumeRustString()
            json?.let { ServerPassword.fromJSON(it) }
        }
    }

    @Throws(LoginsStorageException::class)
    override fun touch(id: String) {
        return withQueryMetricsWrite {
            rustCallWithLock { raw, error ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_touch(raw, id, error)
            }
        }
    }

    @Throws(LoginsStorageException::class)
    override fun list(): List<ServerPassword> {
        return withQueryMetricsRead {
            val json = rustCallWithLock { raw, error ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_get_all(raw, error)
            }.getAndConsumeRustString()
            ServerPassword.fromJSONArray(json)
            // XXX TODO: we could set snapshot metrics here, since we
            // just ready all the logins into memory
        }
    }

    @Throws(LoginsStorageException::class)
    override fun getByHostname(hostname: String): List<ServerPassword> {
        return withQueryMetricsRead {
            val json = rustCallWithLock { raw, error ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_get_by_hostname(raw, hostname, error)
            }.getAndConsumeRustString()
            ServerPassword.fromJSONArray(json)
        }
    }

    @Throws(LoginsStorageException::class)
    override fun add(login: ServerPassword): String {
        return withQueryMetricsWrite {
            val s = login.toJSON().toString()
            rustCallWithLock { raw, error ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_add(raw, s, error)
            }.getAndConsumeRustString()
        }
    }

    @Throws(LoginsStorageException::class)
    override fun importLogins(logins: Array<ServerPassword>): Long {
        val s = JSONArray().apply {
            logins.forEach {
                put(it.toJSON())
            }
        }.toString()
        return withQueryMetricsWrite {
            rustCallWithLock { raw, error ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_import(raw, s, error)
            }
        }
    }

    @Throws(LoginsStorageException::class)
    override fun update(login: ServerPassword) {
        val s = login.toJSON().toString()
        return withQueryMetricsWrite {
            rustCallWithLock { raw, error ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_update(raw, s, error)
            }
        }
    }

    @Synchronized
    @Throws(LoginsStorageException::class)
    override fun close() {
        val handle = this.raw.getAndSet(0)
        if (handle != 0L) {
            rustCall { err ->
                PasswordSyncAdapter.INSTANCE.sync15_passwords_state_destroy(handle, err)
            }
        }
    }

    private fun gatherSnapshotMetrics() {
        // XXX TODO: ask the rust code to return snapshot metrics from the db.
        LoginsStoreMetrics.loginLastUsedDays.accumulateSamples(longArrayOf(1L,2L,3L,4L,5L))
        // XXX TODO: hmm, histogram probably won't work here as we can't clear it to set the new value,
        // this will just *add* the current count to the set of existing values.
        LoginsStoreMetrics.numSavedPasswords.accumulateSamples(longArrayOf(42L))
    }

    private inline fun <U> withQueryMetricsRead(callback: () -> U): U {
        LoginsStoreMetrics.readQueryCount.add()
        try {
            val timer = LoginsStoreMetrics.readQueryTime.start()
            try {
                return callback()
            } finally {
                LoginsStoreMetrics.readQueryTime.stopAndAccumulate(timer)
            }
        } catch (e: Exception) {
            LoginsStoreMetrics.readQueryErrorCount["some_label"].add()
            throw e
        }
    }

    private inline fun <U> withQueryMetricsWrite(callback: () -> U): U {
        LoginsStoreMetrics.writeQueryCount.add()
        try {
            val timer = LoginsStoreMetrics.writeQueryTime.start()
            try {
                return callback()
            } finally {
                LoginsStoreMetrics.writeQueryTime.stopAndAccumulate(timer)
            }
        } catch (e: Exception) {
            LoginsStoreMetrics.writeQueryErrorCount["some_label"].add()
            throw e
        }
    }

    // In practice we usually need to be synchronized to call this safely, so it doesn't
    // synchronize itself
    private inline fun <U> nullableRustCall(callback: (RustError.ByReference) -> U?): U? {
        val e = RustError.ByReference()
        try {
            val ret = callback(e)
            if (e.isFailure()) {
                throw e.intoException()
            }
            return ret
        } finally {
            // This only matters if `callback` throws (or does a non-local return, which
            // we currently don't do)
            e.ensureConsumed()
        }
    }

    private inline fun <U> rustCall(callback: (RustError.ByReference) -> U?): U {
        return nullableRustCall(callback)!!
    }

    private inline fun <U> nullableRustCallWithLock(callback: (Long, RustError.ByReference) -> U?): U? {
        return synchronized(this) {
            val handle = checkUnlocked()
            nullableRustCall { callback(handle, it) }
        }
    }

    private inline fun <U> rustCallWithLock(callback: (Long, RustError.ByReference) -> U?): U {
        return nullableRustCallWithLock(callback)!!
    }
}

/**
 * Helper to read a null terminated String out of the Pointer and free it.
 *
 * Important: Do not use this pointer after this! For anything!
 */
internal fun Pointer.getAndConsumeRustString(): String {
    try {
        return this.getRustString()
    } finally {
        PasswordSyncAdapter.INSTANCE.sync15_passwords_destroy_string(this)
    }
}

/**
 * Helper to read a null terminated string out of the pointer.
 *
 * Important: doesn't free the pointer, use [getAndConsumeRustString] for that!
 */
internal fun Pointer.getRustString(): String {
    return this.getString(0, "utf8")
}
