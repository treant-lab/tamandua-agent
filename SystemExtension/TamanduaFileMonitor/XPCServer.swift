/// XPCServer.swift
/// XPC service for communication between System Extension and main Tamandua agent
///
/// This class implements a Mach-based XPC service that allows the main agent
/// to receive file events and control the System Extension.
///
/// Protocol:
/// - getEvents() -> [FileEvent]: Retrieve queued file events
/// - setMutedPaths(_ paths: [String]): Update muted paths
/// - setBlockingEnabled(_ enabled: Bool): Enable/disable blocking mode
/// - getStats() -> ESClientStats: Get monitoring statistics
/// - getHealth() -> [String: String]: Get capability/prerequisite status

import Foundation
import os.log

/// Logger for XPC server operations
private let logger = Logger(subsystem: "com.tamandua.agent.sysext", category: "XPCServer")

// MARK: - XPC Protocol

/// Protocol for communication with the main agent
@objc public protocol TamanduaXPCProtocol {
    /// Retrieve queued file events
    func getEvents(reply: @escaping ([Data]) -> Void)

    /// Update muted paths
    func setMutedPaths(_ paths: [String], reply: @escaping (Bool) -> Void)

    /// Enable or disable blocking mode
    func setBlockingEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)

    /// Get current statistics
    func getStats(reply: @escaping ([String: UInt64]) -> Void)

    /// Get current capability/prerequisite health
    func getHealth(reply: @escaping ([String: String]) -> Void)

    /// Ping for health check
    func ping(reply: @escaping (String) -> Void)
}

// MARK: - XPCServer

/// XPC server for the System Extension
public final class XPCServer: NSObject, @unchecked Sendable {
    /// Mach service name
    private static let serviceName = "com.tamandua.agent.filemonitor"

    /// XPC listener
    private var listener: NSXPCListener?

    /// Event queue
    private var eventQueue = EventQueue()

    /// Configuration callback (set by owner)
    public var onSetMutedPaths: (([String]) -> Void)?
    public var onSetBlockingEnabled: ((Bool) -> Void)?
    public var onGetStats: (() -> ESClientStats)?
    public var onGetHealth: (() -> [String: String])?

    /// Active connections (for cleanup)
    private var connections = Set<NSXPCConnection>()
    private let connectionLock = NSLock()

    // MARK: - Initialization

    public override init() {
        super.init()
        logger.info("XPCServer initialized")
    }

    deinit {
        stop()
    }

    // MARK: - Lifecycle

    /// Start the XPC server
    public func start() throws {
        guard listener == nil else {
            logger.warning("XPCServer already running")
            return
        }

        // Create listener for Mach service
        listener = NSXPCListener(machServiceName: XPCServer.serviceName)
        listener?.delegate = self
        listener?.resume()

        logger.info("XPCServer started on \(XPCServer.serviceName)")
    }

    /// Stop the XPC server
    public func stop() {
        listener?.invalidate()
        listener = nil

        // Invalidate all connections
        connectionLock.lock()
        for connection in connections {
            connection.invalidate()
        }
        connections.removeAll()
        connectionLock.unlock()

        logger.info("XPCServer stopped")
    }

    // MARK: - Event Queue

    /// Add an event to the queue
    public func enqueueEvent(_ event: FileEvent) {
        eventQueue.enqueue(event)
    }

    /// Get number of queued events
    public var queuedEventCount: Int {
        eventQueue.count
    }
}

// MARK: - NSXPCListenerDelegate

extension XPCServer: NSXPCListenerDelegate {
    public func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // Configure the connection
        newConnection.exportedInterface = NSXPCInterface(with: TamanduaXPCProtocol.self)
        newConnection.exportedObject = self

        // Handle connection invalidation
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let self = self, let connection = newConnection else { return }
            self.connectionLock.lock()
            self.connections.remove(connection)
            self.connectionLock.unlock()
            logger.debug("XPC connection invalidated")
        }

        // Handle connection interruption
        newConnection.interruptionHandler = {
            logger.warning("XPC connection interrupted")
        }

        // Track connection
        connectionLock.lock()
        connections.insert(newConnection)
        connectionLock.unlock()

        // Resume the connection
        newConnection.resume()

        logger.info("Accepted XPC connection from PID \(newConnection.processIdentifier)")
        return true
    }
}

// MARK: - TamanduaXPCProtocol Implementation

extension XPCServer: TamanduaXPCProtocol {
    public func getEvents(reply: @escaping ([Data]) -> Void) {
        let events = eventQueue.dequeueAll()
        let encoder = JSONEncoder()

        let data: [Data] = events.compactMap { event in
            try? encoder.encode(event)
        }

        reply(data)
    }

    public func setMutedPaths(_ paths: [String], reply: @escaping (Bool) -> Void) {
        if let callback = onSetMutedPaths {
            callback(paths)
            reply(true)
        } else {
            reply(false)
        }
    }

    public func setBlockingEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        if let callback = onSetBlockingEnabled {
            callback(enabled)
            reply(true)
        } else {
            reply(false)
        }
    }

    public func getStats(reply: @escaping ([String: UInt64]) -> Void) {
        if let callback = onGetStats {
            let stats = callback()
            reply([
                "totalEvents": stats.totalEvents,
                "authEvents": stats.authEvents,
                "notifyEvents": stats.notifyEvents,
                "unknownEvents": stats.unknownEvents,
                "droppedEvents": stats.droppedEvents,
                "queuedEvents": UInt64(eventQueue.count)
            ])
        } else {
            reply([:])
        }
    }

    public func getHealth(reply: @escaping ([String: String]) -> Void) {
        if let callback = onGetHealth {
            reply(callback())
        } else {
            reply([
                "state": "degraded",
                "reason": "ESClient health callback is not registered"
            ])
        }
    }

    public func ping(reply: @escaping (String) -> Void) {
        reply("pong")
    }
}

// MARK: - EventQueue

/// Thread-safe event queue with max size limit
private final class EventQueue: @unchecked Sendable {
    /// Maximum number of events to queue
    private let maxSize: Int

    /// Event storage
    private var events: [FileEvent] = []

    /// Lock for thread safety
    private let lock = NSLock()

    /// Number of dropped events
    private(set) var droppedCount: UInt64 = 0

    init(maxSize: Int = 10000) {
        self.maxSize = maxSize
        events.reserveCapacity(maxSize)
    }

    /// Current queue size
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return events.count
    }

    /// Add an event to the queue
    func enqueue(_ event: FileEvent) {
        lock.lock()
        defer { lock.unlock() }

        if events.count >= maxSize {
            // Drop oldest event
            events.removeFirst()
            droppedCount += 1
        }

        events.append(event)
    }

    /// Remove and return all events
    func dequeueAll() -> [FileEvent] {
        lock.lock()
        defer { lock.unlock() }

        let result = events
        events.removeAll(keepingCapacity: true)
        return result
    }

    /// Remove and return up to `limit` events
    func dequeue(limit: Int) -> [FileEvent] {
        lock.lock()
        defer { lock.unlock() }

        let count = min(limit, events.count)
        let result = Array(events.prefix(count))
        events.removeFirst(count)
        return result
    }
}
