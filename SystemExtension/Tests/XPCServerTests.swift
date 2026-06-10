/// XPCServerTests.swift
/// Unit tests for XPCServer
///
/// Note: These tests verify the XPCServer structure and queue behavior.
/// Full XPC testing requires running on macOS with proper service registration.

import XCTest
@testable import TamanduaFileMonitor

final class XPCServerTests: XCTestCase {

    // MARK: - Initialization Tests

    func testXPCServerInitialization() {
        let server = XPCServer()
        XCTAssertNotNil(server)
        XCTAssertEqual(server.queuedEventCount, 0)
    }

    // MARK: - Event Queue Tests

    func testEnqueueEvent() {
        let server = XPCServer()

        let event = FileEvent(
            eventType: "open",
            path: "/tmp/test.txt",
            pid: 123,
            processPath: "/bin/cat",
            uid: 501,
            gid: 20,
            timestamp: 12345,
            isAuth: false
        )

        server.enqueueEvent(event)
        XCTAssertEqual(server.queuedEventCount, 1)
    }

    func testEnqueueMultipleEvents() {
        let server = XPCServer()

        for i in 0..<100 {
            let event = FileEvent(
                eventType: "write",
                path: "/tmp/test\(i).txt",
                pid: pid_t(i),
                processPath: "/bin/cat",
                uid: 501,
                gid: 20,
                timestamp: UInt64(i),
                isAuth: false
            )
            server.enqueueEvent(event)
        }

        XCTAssertEqual(server.queuedEventCount, 100)
    }

    // MARK: - Callback Tests

    func testSetMutedPathsCallback() {
        let server = XPCServer()
        var receivedPaths: [String]?

        server.onSetMutedPaths = { paths in
            receivedPaths = paths
        }

        let expectation = XCTestExpectation(description: "Callback received")
        server.setMutedPaths(["/test/path"]) { success in
            XCTAssertTrue(success)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
        XCTAssertEqual(receivedPaths, ["/test/path"])
    }

    func testSetBlockingEnabledCallback() {
        let server = XPCServer()
        var receivedEnabled: Bool?

        server.onSetBlockingEnabled = { enabled in
            receivedEnabled = enabled
        }

        let expectation = XCTestExpectation(description: "Callback received")
        server.setBlockingEnabled(true) { success in
            XCTAssertTrue(success)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
        XCTAssertEqual(receivedEnabled, true)
    }

    func testGetStatsCallback() {
        let server = XPCServer()

        server.onGetStats = {
            var stats = ESClientStats()
            stats.totalEvents = 100
            stats.authEvents = 50
            stats.notifyEvents = 50
            return stats
        }

        let expectation = XCTestExpectation(description: "Stats received")
        server.getStats { stats in
            XCTAssertEqual(stats["totalEvents"], 100)
            XCTAssertEqual(stats["authEvents"], 50)
            XCTAssertEqual(stats["notifyEvents"], 50)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }

    func testPing() {
        let server = XPCServer()

        let expectation = XCTestExpectation(description: "Ping response")
        server.ping { response in
            XCTAssertEqual(response, "pong")
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }

    func testGetHealthCallback() {
        let server = XPCServer()

        server.onGetHealth = {
            [
                "state": "ready",
                "endpointSecurity": "connected"
            ]
        }

        let expectation = XCTestExpectation(description: "Health received")
        server.getHealth { health in
            XCTAssertEqual(health["state"], "ready")
            XCTAssertEqual(health["endpointSecurity"], "connected")
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }

    // MARK: - Missing Callback Tests

    func testSetMutedPathsWithoutCallback() {
        let server = XPCServer()
        // No callback set

        let expectation = XCTestExpectation(description: "Callback returns false")
        server.setMutedPaths(["/test"]) { success in
            XCTAssertFalse(success)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }

    func testSetBlockingEnabledWithoutCallback() {
        let server = XPCServer()
        // No callback set

        let expectation = XCTestExpectation(description: "Callback returns false")
        server.setBlockingEnabled(true) { success in
            XCTAssertFalse(success)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }

    func testGetHealthWithoutCallbackReportsDegraded() {
        let server = XPCServer()

        let expectation = XCTestExpectation(description: "Health returns degraded")
        server.getHealth { health in
            XCTAssertEqual(health["state"], "degraded")
            XCTAssertNotNil(health["reason"])
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }
}
