package org.microg.gms.accountaction

import android.accounts.Account
import android.content.Context
import android.content.Intent
import android.os.Build.VERSION.SDK_INT
import android.util.Log
import kotlinx.coroutines.runBlocking
import org.microg.gms.auth.login.LoginActivity
import org.microg.gms.checkin.CheckinManager
import org.microg.gms.checkin.LastCheckinInfo
import org.microg.gms.common.Constants
import org.microg.gms.cryptauth.isLockscreenConfigured
import org.microg.gms.cryptauth.sendDeviceScreenlockState
import org.microg.gms.gcm.GcmDatabase
import org.microg.gms.gcm.GcmPrefs
import org.microg.gms.gcm.McsService
import org.microg.gms.settings.SettingsContract
import java.io.IOException


/**
 * High-level resolution: tell server that user has configured a lock screen
 */
const val DEVICE_MANAGEMENT_SCREENLOCK_REQUIRED = "DeviceManagementScreenlockRequired"

/**
 * Indicates that the user is using an enterprise account that is set up to use Advanced
 * device management features, for which it is required to install a device manager.
 * This is not supported by microG.
 */
const val DEVICE_MANAGEMENT_REQUIRED = "DeviceManagementRequired"

/**
 * Indicates that the user is using an enterprise account that is set up to use Advanced
 * device management features, for which it is required to install a device manager,
 * and that the device also needs manual admin approval.
 * This is not supported by microG.
 */
const val DEVICE_MANAGEMENT_ADMIN_PENDING_APPROVAL = "DeviceManagementAdminPendingApproval"

/**
 * Indicates that the token stored on the device is no longer valid.
 */
const val BAD_AUTHENTICATION = "BadAuthentication"

const val SERVER_ERROR = "Error 500"

/**
 * The account is supervised (Family Link) and the server requires the device to be enrolled in
 * third-party device management (a supervision DPC). Observed wire form is a multi-line body
 * "Error=ThirdPartyDeviceManagementRequired\nErrorCode=SupervisionDM". microG cannot satisfy this,
 * but a freshly registered device is granted a grace window, so we mitigate by re-registering.
 */
const val THIRD_PARTY_DEVICE_MANAGEMENT_REQUIRED = "ThirdPartyDeviceManagementRequired"
const val SUPERVISION_DM = "SupervisionDM"

private const val SUPERVISION_RECOVERY_PREFS = "auth_supervision_recovery"
private const val SUPERVISION_RECOVERY_LAST = "last_reregister"

// A new androidId invalidates every app's push token and the server re-flags the registration after
// its grace window, so re-registration must be rate-limited to avoid push churn and an endless loop.
private const val MIN_REREGISTER_INTERVAL = 6 * 60 * 60 * 1000L // 6 hours

const val TAG = "GmsAccountErrorResolve"

/**
 * @return `null` if it is unknown how to resolve the problem, an
 * appropriate `Resolution` otherwise
 */
/**
 * Whether an auth error response denotes a supervised (Family Link) account that the server refuses
 * because the device is not enrolled in third-party device management. The response body is
 * multi-line ("Error=ThirdPartyDeviceManagementRequired\nErrorCode=SupervisionDM"), so this matches
 * with [String.contains] rather than equality. Pure (no Context) so it can be unit-tested.
 */
internal fun isSupervisionDeviceManagementError(message: String): Boolean =
    message.contains(THIRD_PARTY_DEVICE_MANAGEMENT_REQUIRED) || message.contains(SUPERVISION_DM)

fun Context.resolveAuthErrorMessage(s: String): Resolution? = if (s.startsWith("Error=")) {
    resolveAuthErrorMessage(s.drop("Error=".length))
} else if (s.contains(SERVER_ERROR)) {
    Reauthenticate
} else if (isSupervisionDeviceManagementError(s)) {
    ReRegisterDevice
} else when (s) {
    DEVICE_MANAGEMENT_SCREENLOCK_REQUIRED -> listOf(
        Requirement.ENABLE_CHECKIN,
        Requirement.ENABLE_GCM,
        Requirement.ALLOW_MICROG_GCM,
        Requirement.ENABLE_LOCKSCREEN
    )
        .associateWith { checkRequirementSatisfied(it) }
        .filterValues { satisfied -> !satisfied }.let {
            if (it.isEmpty()) {
                // all requirements are satisfied, crypt auth sync keys can be run
                CryptAuthSyncKeys
            } else {
                // prompt user to satisfy missing requirements
                UserSatisfyRequirements(it.keys)
            }
        }

    DEVICE_MANAGEMENT_ADMIN_PENDING_APPROVAL, DEVICE_MANAGEMENT_REQUIRED ->
        NoResolution(NoResolutionReason.ADVANCED_DEVICE_MANAGEMENT_NOT_SUPPORTED)

    BAD_AUTHENTICATION -> Reauthenticate

    else -> null
}.also { Log.d(TAG, "Error was: $s. Diagnosis: $it.") }

fun Context.checkRequirementSatisfied(requirement: Requirement): Boolean = when (requirement) {
    Requirement.ENABLE_CHECKIN -> isCheckinEnabled()
    Requirement.ENABLE_GCM -> isGcmEnabled()
    Requirement.ALLOW_MICROG_GCM -> isMicrogAppGcmAllowed()
    Requirement.ENABLE_LOCKSCREEN -> isLockscreenConfigured()
}

fun Context.isCheckinEnabled(): Boolean {
    val settingsProjection = arrayOf(
        SettingsContract.CheckIn.ENABLED,
        SettingsContract.CheckIn.LAST_CHECK_IN
    )
    return SettingsContract.getSettings(this, SettingsContract.CheckIn.getContentUri(this), settingsProjection) { cursor ->
        val checkInEnabled = cursor.getInt(0) != 0
        val lastCheckIn = cursor.getLong(1)

        // user is also asked to enable checkin if there had never been a successful checkin (network errors?)
        lastCheckIn > 0 && checkInEnabled
    }
}

fun Context.isGcmEnabled(): Boolean = GcmPrefs.get(this).isEnabled

/**
 * Automates the manual "clear storage" workaround for supervised (Family Link) accounts that the
 * server refuses with [THIRD_PARTY_DEVICE_MANAGEMENT_REQUIRED]. Discards the current device
 * registration so the next check-in mints a fresh androidId (a new registration that the server
 * grants a grace window before re-enforcing supervision device management), then nudges MCS to
 * reconnect under the new id. The account and its master token live in the system AccountManager,
 * so no re-login is needed. Rate-limited and restores the previous registration on failure.
 *
 * @return true if a fresh androidId was minted and the caller should retry the token request
 */
private fun Context.reRegisterDeviceForSupervision(): Boolean {
    if (!isCheckinEnabled()) {
        Log.w(TAG, "Cannot re-register for supervised account: check-in is disabled")
        return false
    }
    val prefs = getSharedPreferences(SUPERVISION_RECOVERY_PREFS, Context.MODE_PRIVATE)
    val now = System.currentTimeMillis()
    val last = prefs.getLong(SUPERVISION_RECOVERY_LAST, 0L)
    if (last != 0L && now - last < MIN_REREGISTER_INTERVAL) {
        Log.d(TAG, "Supervised device was re-registered recently; not retrying")
        return false
    }
    // Stamp before acting so concurrent failing token requests back off instead of all re-registering.
    prefs.edit().putLong(SUPERVISION_RECOVERY_LAST, now).apply()

    val previous = LastCheckinInfo.read(this)
    LastCheckinInfo.clear(this)
    val updated = try {
        CheckinManager.checkin(this, true)
    } catch (e: Exception) {
        Log.w(TAG, "Supervised re-registration check-in failed; restoring previous registration", e)
        previous.write(this)
        return false
    }
    if (updated == null || updated.androidId == 0L) {
        Log.w(TAG, "Supervised re-registration yielded no androidId; restoring previous registration")
        previous.write(this)
        return false
    }
    Log.d(TAG, "Re-registered device for supervised account; new androidId minted, reconnecting MCS")
    McsService.scheduleReconnect(this)
    return true
}

fun Context.isMicrogAppGcmAllowed(): Boolean {
    val gcmPrefs = GcmPrefs.get(this)
    val gcmDatabaseEntry = GcmDatabase(this).use {
        it.getApp(Constants.GMS_PACKAGE_NAME)
    }
    return !(gcmDatabaseEntry != null &&
            !gcmDatabaseEntry.allowRegister ||
            gcmDatabaseEntry == null &&
            gcmPrefs.confirmNewApps)

}

fun <T> Resolution.initiateFromBackgroundBlocking(context: Context, account: Account, retryFunction: RetryFunction<T>): T? {
    when (this) {
        CryptAuthSyncKeys -> {
            Log.d(TAG, "Resolving account error by performing cryptauth sync keys call.")
            runBlocking {
                context.sendDeviceScreenlockState(account)
            }
            return retryFunction.run()
        }
        is NoResolution -> {
            Log.w(TAG, "This account cannot be used with microG due to $reason")
            return null
        }
        is UserSatisfyRequirements -> {
            Log.w(TAG, "User intervention required! You need to ${actions.joinToString(", ")}.")
            if (SDK_INT >= 21) {
                context.sendAccountActionNotification(account, this)
            }
            return null
        }
        Reauthenticate -> {
            Log.w(TAG, "Your account credentials have expired! Please remove the account, then sign in again.")
            if (SDK_INT >= 21) {
                context.sendAccountReAuthNotification(account)
            }
            return null
        }
        ReRegisterDevice -> {
            Log.d(TAG, "Resolving supervised-account device-management error by re-registering the device.")
            return if (context.reRegisterDeviceForSupervision()) retryFunction.run() else null
        }
    }
}

fun <T> Resolution.initiateFromForegroundBlocking(context: Context, account: Account, retryFunction: RetryFunction<T>): T? {
    when (this) {
        CryptAuthSyncKeys -> {
            Log.d(TAG, "Resolving account error by performing cryptauth sync keys call.")
            runBlocking {
                context.sendDeviceScreenlockState(account)
            }
            return retryFunction.run()
        }
        is NoResolution -> {
            Log.w(TAG, "This account cannot be used with microG due to $reason")
            return null
        }
        is UserSatisfyRequirements -> {
            Log.w(TAG, "User intervention required! You need to ${actions.joinToString(", ")}.")
            if (SDK_INT >= 21) {
                AccountActionActivity.createIntent(context, account, this).let {
                    context.startActivity(it)
                }
            }
            return null
        }
        Reauthenticate -> {
            Log.w(TAG, "Your account credentials have expired! Please remove the account, then sign in again.")
            Intent(context, LoginActivity::class.java).apply {
                putExtra(LoginActivity.EXTRA_RE_AUTH_ACCOUNT, account)
            }.let {
                context.startActivity(it)
            }
            return null
        }
        ReRegisterDevice -> {
            Log.d(TAG, "Resolving supervised-account device-management error by re-registering the device.")
            return if (context.reRegisterDeviceForSupervision()) retryFunction.run() else null
        }
    }
}

interface RetryFunction<T> {
    @Throws(IOException::class)
    fun run(): T
}