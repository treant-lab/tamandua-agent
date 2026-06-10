/// TamanduaFileMonitor.swift
/// Main entry point for the Tamandua File Monitor System Extension
///
/// This System Extension uses EndpointSecurity.framework to monitor file system
/// operations and forward events to the main Tamandua agent via XPC.
///
/// Requirements:
/// - macOS 11.0 (Big Sur) or later
/// - com.apple.developer.endpoint-security.client entitlement
/// - com.apple.developer.system-extension.install entitlement
/// - Code signing with Developer ID certificate

import Foundation
import EndpointSecurity
import os.log

// MARK: - Logging

/// Unified logging for the System Extension
private let logger = Logger(subsystem: "com.tamandua.agent.sysext", category: "FileMonitor")

// MARK: - Main Entry Point

/// System Extension entry point
@main
struct TamanduaFileMonitor {
    static func main() {
        logger.info("TamanduaFileMonitor starting...")

        // Initialize components
        let xpcServer = XPCServer()
        let esClient: ESClient

        do {
            esClient = try ESClient(eventHandler: { event in
                xpcServer.enqueueEvent(event)
            })
        } catch {
            logger.error("Failed to initialize ESClient: \(error.localizedDescription)")
            exit(1)
        }

        xpcServer.onSetMutedPaths = { paths in
            esClient.setMutedPaths(paths)
        }
        xpcServer.onSetBlockingEnabled = { enabled in
            esClient.setBlockingEnabled(enabled)
        }
        xpcServer.onGetStats = {
            esClient.getStats()
        }
        xpcServer.onGetHealth = {
            esClient.getHealth()
        }

        // Start XPC server
        do {
            try xpcServer.start()
        } catch {
            logger.error("Failed to start XPC server: \(error.localizedDescription)")
            exit(1)
        }

        // Start ES monitoring
        do {
            try esClient.start()
        } catch {
            logger.error("Failed to start ES monitoring: \(error.localizedDescription)")
            exit(1)
        }

        logger.info("TamanduaFileMonitor running")

        // Register for termination signals
        signal(SIGTERM) { _ in
            logger.info("Received SIGTERM, shutting down...")
            exit(0)
        }

        signal(SIGINT) { _ in
            logger.info("Received SIGINT, shutting down...")
            exit(0)
        }

        // Run forever (System Extension lifecycle is managed by macOS)
        dispatchMain()
    }
}

// MARK: - FileEvent Structure

/// Represents a file system event for transmission to the agent
public struct FileEvent: Codable, Sendable {
    /// Unique event identifier
    public let eventId: String

    /// Event type (open, create, write, close, rename, unlink)
    public let eventType: String

    /// Full path to the affected file
    public let path: String

    /// Path before operation (for rename events)
    public let oldPath: String?

    /// Process ID that triggered the event
    public let pid: pid_t

    /// Process path
    public let processPath: String

    /// Process signing ID (if signed)
    public let signingId: String?

    /// Process team ID (if signed)
    public let teamId: String?

    /// User ID
    public let uid: uid_t

    /// Group ID
    public let gid: gid_t

    /// Event timestamp (nanoseconds since boot)
    public let timestamp: UInt64

    /// Whether this was an AUTH event (vs NOTIFY)
    public let isAuth: Bool

    /// Whether the operation was allowed (for AUTH events)
    public let allowed: Bool

    public init(
        eventId: String = UUID().uuidString,
        eventType: String,
        path: String,
        oldPath: String? = nil,
        pid: pid_t,
        processPath: String,
        signingId: String? = nil,
        teamId: String? = nil,
        uid: uid_t,
        gid: gid_t,
        timestamp: UInt64,
        isAuth: Bool,
        allowed: Bool = true
    ) {
        self.eventId = eventId
        self.eventType = eventType
        self.path = path
        self.oldPath = oldPath
        self.pid = pid
        self.processPath = processPath
        self.signingId = signingId
        self.teamId = teamId
        self.uid = uid
        self.gid = gid
        self.timestamp = timestamp
        self.isAuth = isAuth
        self.allowed = allowed
    }
}

// MARK: - Configuration

/// Configuration for the file monitor
public struct FileMonitorConfig: Codable, Sendable {
    /// Paths to mute (not monitor)
    public var mutedPaths: [String]

    /// Whether to enable blocking mode for AUTH events
    public var blockingEnabled: Bool

    /// Maximum events to queue before dropping
    public var maxQueueSize: Int

    /// Event types to monitor
    public var monitoredEventTypes: [String]

    public init(
        mutedPaths: [String] = [],
        blockingEnabled: Bool = false,
        maxQueueSize: Int = 10000,
        monitoredEventTypes: [String] = ["open", "create", "write", "rename", "unlink"]
    ) {
        self.mutedPaths = mutedPaths
        self.blockingEnabled = blockingEnabled
        self.maxQueueSize = maxQueueSize
        self.monitoredEventTypes = monitoredEventTypes
    }

    /// Default configuration with system paths muted
    public static var `default`: FileMonitorConfig {
        FileMonitorConfig(
            mutedPaths: [
                "/System",
                "/usr",
                "/Library/Apple",
                "/private/var/db",
                "/private/var/folders"
            ],
            blockingEnabled: false,
            maxQueueSize: 10000,
            monitoredEventTypes: ["open", "create", "write", "rename", "unlink"]
        )
    }
}
