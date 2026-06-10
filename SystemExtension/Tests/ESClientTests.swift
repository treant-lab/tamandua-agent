/// ESClientTests.swift
/// Unit tests for ESClient
///
/// Note: These tests verify the ESClient structure and error handling.
/// Full ES testing requires running on macOS with proper entitlements.

import XCTest
@testable import TamanduaFileMonitor

final class ESClientTests: XCTestCase {

    // MARK: - Initialization Tests

    func testESClientInitializationCreatesInstance() throws {
        // This test verifies that ESClient can be instantiated
        // Note: On non-macOS or without entitlements, ES operations will fail
        var receivedEvents: [FileEvent] = []

        let client = try ESClient { event in
            receivedEvents.append(event)
        }

        XCTAssertNotNil(client)
    }

    // MARK: - FileEvent Tests

    func testFileEventSerialization() throws {
        let event = FileEvent(
            eventId: "test-123",
            eventType: "open",
            path: "/tmp/testfile.txt",
            oldPath: nil,
            pid: 1234,
            processPath: "/usr/bin/cat",
            signingId: "com.apple.cat",
            teamId: "AAPL",
            uid: 501,
            gid: 20,
            timestamp: 123456789,
            isAuth: true,
            allowed: true
        )

        // Verify encoding
        let encoder = JSONEncoder()
        let data = try encoder.encode(event)
        XCTAssertFalse(data.isEmpty)

        // Verify decoding
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(FileEvent.self, from: data)
        XCTAssertEqual(decoded.eventId, event.eventId)
        XCTAssertEqual(decoded.eventType, event.eventType)
        XCTAssertEqual(decoded.path, event.path)
        XCTAssertEqual(decoded.pid, event.pid)
        XCTAssertEqual(decoded.processPath, event.processPath)
    }

    func testFileEventWithRename() throws {
        let event = FileEvent(
            eventType: "rename",
            path: "/tmp/newname.txt",
            oldPath: "/tmp/oldname.txt",
            pid: 5678,
            processPath: "/bin/mv",
            uid: 501,
            gid: 20,
            timestamp: 987654321,
            isAuth: false
        )

        XCTAssertEqual(event.eventType, "rename")
        XCTAssertEqual(event.path, "/tmp/newname.txt")
        XCTAssertEqual(event.oldPath, "/tmp/oldname.txt")
        XCTAssertFalse(event.isAuth)
    }

    // MARK: - Configuration Tests

    func testDefaultConfiguration() {
        let config = FileMonitorConfig.default

        XCTAssertFalse(config.mutedPaths.isEmpty)
        XCTAssertTrue(config.mutedPaths.contains("/System"))
        XCTAssertTrue(config.mutedPaths.contains("/usr"))
        XCTAssertFalse(config.blockingEnabled)
        XCTAssertEqual(config.maxQueueSize, 10000)
    }

    func testCustomConfiguration() {
        let config = FileMonitorConfig(
            mutedPaths: ["/custom/path"],
            blockingEnabled: true,
            maxQueueSize: 5000,
            monitoredEventTypes: ["open", "write"]
        )

        XCTAssertEqual(config.mutedPaths, ["/custom/path"])
        XCTAssertTrue(config.blockingEnabled)
        XCTAssertEqual(config.maxQueueSize, 5000)
        XCTAssertEqual(config.monitoredEventTypes, ["open", "write"])
    }

    // MARK: - Error Description Tests

    func testESClientErrorDescriptions() {
        let notEntitledError = ESClientError.clientCreationFailed(ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED)
        XCTAssertTrue(notEntitledError.errorDescription?.contains("Not entitled") ?? false)
        XCTAssertEqual(notEntitledError.prerequisiteCode, "missing_entitlement")

        let notPermittedError = ESClientError.clientCreationFailed(ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED)
        XCTAssertEqual(notPermittedError.prerequisiteCode, "not_permitted_tcc_or_fda")

        let notRunningError = ESClientError.notRunning
        XCTAssertTrue(notRunningError.errorDescription?.contains("not running") ?? false)
        XCTAssertEqual(notRunningError.prerequisiteCode, "not_running")
    }

    // MARK: - Statistics Tests

    func testESClientStatsDefaults() {
        let stats = ESClientStats()

        XCTAssertEqual(stats.totalEvents, 0)
        XCTAssertEqual(stats.authEvents, 0)
        XCTAssertEqual(stats.notifyEvents, 0)
        XCTAssertEqual(stats.unknownEvents, 0)
        XCTAssertEqual(stats.droppedEvents, 0)
    }

    func testESClientHealthDefaultsToDegradedBeforeStart() throws {
        let client = try ESClient { _ in }
        let health = client.getHealth()

        XCTAssertEqual(health["state"], "degraded")
        XCTAssertEqual(health["endpointSecurity"], "not_running")
        XCTAssertEqual(health["requiredEntitlement"], "com.apple.developer.endpoint-security.client")
    }
}
