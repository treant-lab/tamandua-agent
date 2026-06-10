/// ESClient.swift
/// EndpointSecurity client wrapper for file monitoring
///
/// This class wraps the EndpointSecurity.framework C API in a Swift-friendly interface.
/// It handles ES client lifecycle, event subscription, and message processing.
///
/// Thread Safety:
/// - ES callbacks run on a dedicated ES dispatch queue
/// - Event handler closure must be thread-safe
/// - Configuration updates are synchronized via dispatch queue

import Foundation
import EndpointSecurity
import os.log

/// Logger for ES client operations
private let logger = Logger(subsystem: "com.tamandua.agent.sysext", category: "ESClient")

// MARK: - ESClient

/// EndpointSecurity client for file monitoring
public final class ESClient: @unchecked Sendable {
    /// ES client handle
    private var client: OpaquePointer?

    /// Event handler callback
    private let eventHandler: @Sendable (FileEvent) -> Void

    /// Configuration
    private var config: FileMonitorConfig

    /// Serial queue for configuration updates
    private let configQueue = DispatchQueue(label: "com.tamandua.esclient.config")

    /// Whether the client is currently running
    private var isRunning = false

    /// Last startup error, retained for health reporting
    private var lastStartupError: ESClientError?

    /// Statistics
    private var stats = ESClientStats()

    // MARK: - Initialization

    /// Initialize the ES client
    /// - Parameter eventHandler: Callback for processed file events
    /// - Throws: ESClientError if initialization fails
    public init(eventHandler: @escaping @Sendable (FileEvent) -> Void) throws {
        self.eventHandler = eventHandler
        self.config = .default

        logger.info("ESClient initialized")
    }

    deinit {
        stop()
    }

    // MARK: - Lifecycle

    /// Start monitoring file system events
    public func start() throws {
        guard !isRunning else {
            logger.warning("ESClient already running")
            return
        }

        // Create ES client with handler
        let handlerBlock: es_handler_block_t = { [weak self] client, message in
            self?.handleMessage(message)
        }

        let result = es_new_client(&client, handlerBlock)
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            let error = ESClientError.clientCreationFailed(result)
            lastStartupError = error
            throw error
        }

        // Subscribe to events
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_AUTH_EXEC
        ]

        let subscribeResult = es_subscribe(client!, events, UInt32(events.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            es_delete_client(client!)
            client = nil
            let error = ESClientError.subscriptionFailed(subscribeResult)
            lastStartupError = error
            throw error
        }

        // Mute system paths
        muteDefaultPaths()

        isRunning = true
        lastStartupError = nil
        logger.info("ESClient started, subscribed to \(events.count) event types")
    }

    /// Stop monitoring
    public func stop() {
        guard isRunning, let client = client else { return }

        let result = es_delete_client(client)
        if result != ES_RETURN_SUCCESS {
            logger.error("Failed to delete ES client: \(String(describing: result))")
        }

        self.client = nil
        isRunning = false
        logger.info("ESClient stopped")
    }

    // MARK: - Configuration

    /// Update muted paths
    public func setMutedPaths(_ paths: [String]) {
        configQueue.sync {
            config.mutedPaths = paths
        }

        // Apply new muting
        guard let client = client else { return }

        for path in paths {
            let result = es_mute_path_literal(client, path)
            if result != ES_RETURN_SUCCESS {
                logger.warning("Failed to mute path \(path): \(String(describing: result))")
            }
        }

        logger.info("Updated muted paths: \(paths.count) paths")
    }

    /// Enable or disable blocking mode
    public func setBlockingEnabled(_ enabled: Bool) {
        configQueue.sync {
            config.blockingEnabled = enabled
        }
        logger.info("Blocking mode: \(enabled)")
    }

    /// Get current statistics
    public func getStats() -> ESClientStats {
        stats
    }

    /// Get capability/prerequisite health for XPC diagnostics.
    public func getHealth() -> [String: String] {
        var health: [String: String] = [
            "state": isRunning ? "ready" : "degraded",
            "endpointSecurity": isRunning ? "connected" : "not_running",
            "blockingMode": config.blockingEnabled ? "enabled" : "disabled",
            "mutedPathCount": String(config.mutedPaths.count),
            "requiredEntitlement": "com.apple.developer.endpoint-security.client",
            "requiredApproval": "System Extension approval plus Full Disk Access for protected paths"
        ]

        if let error = lastStartupError {
            health["lastErrorCode"] = error.prerequisiteCode
            health["lastError"] = error.errorDescription ?? "unknown"
            health["state"] = "degraded"
        }

        return health
    }

    // MARK: - Private Methods

    /// Mute default system paths
    private func muteDefaultPaths() {
        guard let client = client else { return }

        for path in config.mutedPaths {
            let result = es_mute_path_literal(client, path)
            if result != ES_RETURN_SUCCESS {
                logger.warning("Failed to mute path \(path): \(String(describing: result))")
            }
        }

        // Also mute by process for common system processes
        let systemProcesses = [
            "/usr/libexec/amfid",
            "/usr/libexec/syspolicyd",
            "/usr/sbin/spindump",
            "/usr/sbin/syslogd"
        ]

        for processPath in systemProcesses {
            let result = es_mute_path_literal(client, processPath)
            if result != ES_RETURN_SUCCESS {
                logger.debug("Failed to mute process \(processPath)")
            }
        }

        logger.info("Default paths muted")
    }

    /// Handle an ES message
    private func handleMessage(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        stats.totalEvents += 1

        // Extract process info
        let process = msg.process.pointee
        let pid = audit_token_to_pid(process.audit_token)
        let processPath = extractString(from: process.executable.pointee.path)
        let signingId = extractOptionalString(from: process.signing_id)
        let teamId = extractOptionalString(from: process.team_id)
        let uid = audit_token_to_euid(process.audit_token)
        let gid = audit_token_to_egid(process.audit_token)

        // Create FileEvent based on event type
        var fileEvent: FileEvent?

        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            let openEvent = msg.event.open
            let path = extractString(from: openEvent.file.pointee.path)
            fileEvent = FileEvent(
                eventType: "open",
                path: path,
                pid: pid,
                processPath: processPath,
                signingId: signingId,
                teamId: teamId,
                uid: uid,
                gid: gid,
                timestamp: msg.mach_time,
                isAuth: true
            )
            // Always allow for now (non-blocking mode)
            es_respond_auth_result(client!, message, ES_AUTH_RESULT_ALLOW, true)
            stats.authEvents += 1

        case ES_EVENT_TYPE_AUTH_CREATE:
            let createEvent = msg.event.create
            // Handle both existing file and new path
            let path: String
            if createEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                path = extractString(from: createEvent.destination.existing_file.pointee.path)
            } else {
                let dir = extractString(from: createEvent.destination.new_path.dir.pointee.path)
                let filename = extractString(from: createEvent.destination.new_path.filename)
                path = (dir as NSString).appendingPathComponent(filename)
            }
            fileEvent = FileEvent(
                eventType: "create",
                path: path,
                pid: pid,
                processPath: processPath,
                signingId: signingId,
                teamId: teamId,
                uid: uid,
                gid: gid,
                timestamp: msg.mach_time,
                isAuth: true
            )
            es_respond_auth_result(client!, message, ES_AUTH_RESULT_ALLOW, true)
            stats.authEvents += 1

        case ES_EVENT_TYPE_AUTH_EXEC:
            let execEvent = msg.event.exec
            let path = extractString(from: execEvent.target.pointee.executable.pointee.path)
            fileEvent = FileEvent(
                eventType: "exec",
                path: path,
                pid: pid,
                processPath: processPath,
                signingId: signingId,
                teamId: teamId,
                uid: uid,
                gid: gid,
                timestamp: msg.mach_time,
                isAuth: true
            )
            es_respond_auth_result(client!, message, ES_AUTH_RESULT_ALLOW, true)
            stats.authEvents += 1

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let writeEvent = msg.event.write
            let path = extractString(from: writeEvent.target.pointee.path)
            fileEvent = FileEvent(
                eventType: "write",
                path: path,
                pid: pid,
                processPath: processPath,
                signingId: signingId,
                teamId: teamId,
                uid: uid,
                gid: gid,
                timestamp: msg.mach_time,
                isAuth: false
            )
            stats.notifyEvents += 1

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let closeEvent = msg.event.close
            let path = extractString(from: closeEvent.target.pointee.path)
            fileEvent = FileEvent(
                eventType: "close",
                path: path,
                pid: pid,
                processPath: processPath,
                signingId: signingId,
                teamId: teamId,
                uid: uid,
                gid: gid,
                timestamp: msg.mach_time,
                isAuth: false
            )
            stats.notifyEvents += 1

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let renameEvent = msg.event.rename
            let oldPath = extractString(from: renameEvent.source.pointee.path)
            let newPath: String
            if renameEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                newPath = extractString(from: renameEvent.destination.existing_file.pointee.path)
            } else {
                let dir = extractString(from: renameEvent.destination.new_path.dir.pointee.path)
                let filename = extractString(from: renameEvent.destination.new_path.filename)
                newPath = (dir as NSString).appendingPathComponent(filename)
            }
            fileEvent = FileEvent(
                eventType: "rename",
                path: newPath,
                oldPath: oldPath,
                pid: pid,
                processPath: processPath,
                signingId: signingId,
                teamId: teamId,
                uid: uid,
                gid: gid,
                timestamp: msg.mach_time,
                isAuth: false
            )
            stats.notifyEvents += 1

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let unlinkEvent = msg.event.unlink
            let path = extractString(from: unlinkEvent.target.pointee.path)
            fileEvent = FileEvent(
                eventType: "unlink",
                path: path,
                pid: pid,
                processPath: processPath,
                signingId: signingId,
                teamId: teamId,
                uid: uid,
                gid: gid,
                timestamp: msg.mach_time,
                isAuth: false
            )
            stats.notifyEvents += 1

        default:
            stats.unknownEvents += 1
            return
        }

        if let event = fileEvent {
            eventHandler(event)
        }
    }

    /// Extract a Swift string from an es_string_token_t
    private func extractString(from token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else {
            return ""
        }
        return String(cString: data)
    }

    /// Extract an optional string from an es_string_token_t
    private func extractOptionalString(from token: es_string_token_t) -> String? {
        guard token.length > 0, let data = token.data else {
            return nil
        }
        return String(cString: data)
    }
}

// MARK: - ESClientStats

/// Statistics for ES client operations
public struct ESClientStats: Sendable {
    public var totalEvents: UInt64 = 0
    public var authEvents: UInt64 = 0
    public var notifyEvents: UInt64 = 0
    public var unknownEvents: UInt64 = 0
    public var droppedEvents: UInt64 = 0
}

// MARK: - ESClientError

/// Errors that can occur during ES client operations
public enum ESClientError: Error, LocalizedError {
    case clientCreationFailed(es_new_client_result_t)
    case subscriptionFailed(es_return_t)
    case notRunning

    public var errorDescription: String? {
        switch self {
        case .clientCreationFailed(let result):
            return "Failed to create ES client: \(describeNewClientResult(result))"
        case .subscriptionFailed(let result):
            return "Failed to subscribe to events: \(String(describing: result))"
        case .notRunning:
            return "ES client is not running"
        }
    }

    public var prerequisiteCode: String {
        switch self {
        case .clientCreationFailed(let result):
            return ESClientError.describeNewClientPrerequisite(result)
        case .subscriptionFailed:
            return "subscription_failed"
        case .notRunning:
            return "not_running"
        }
    }

    private func describeNewClientResult(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            return "Success"
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "Invalid argument"
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "Internal error"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "Not entitled (missing com.apple.developer.endpoint-security.client)"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "Not permitted (check System Preferences > Security > Privacy > Full Disk Access)"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "Not privileged (must run as root)"
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "Too many ES clients"
        default:
            return "Unknown error (\(result.rawValue))"
        }
    }

    private static func describeNewClientPrerequisite(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            return "success"
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "invalid_argument"
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "internal"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "missing_entitlement"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "not_permitted_tcc_or_fda"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "not_privileged"
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "too_many_clients"
        default:
            return "unknown"
        }
    }
}
