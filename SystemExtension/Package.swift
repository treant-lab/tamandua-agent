// swift-tools-version: 5.7
// Package.swift - Swift Package Manager configuration for TamanduaFileMonitor System Extension
//
// This package builds a macOS System Extension that uses the EndpointSecurity framework
// to monitor file system operations for threat detection.
//
// Build: swift build --configuration release
// Test:  swift test
//
// Note: System Extensions require code signing with proper entitlements and
// Apple Developer Program membership to run on actual hardware.

import PackageDescription

let package = Package(
    name: "TamanduaFileMonitor",

    platforms: [
        // macOS 11.0 (Big Sur) minimum for modern EndpointSecurity features
        // - ES_EVENT_TYPE_AUTH_* events
        // - es_mute_path_events()
        // - Improved performance and stability
        .macOS(.v11)
    ],

    products: [
        // System Extension executable
        .executable(
            name: "TamanduaFileMonitor",
            targets: ["TamanduaFileMonitor"]
        ),
    ],

    dependencies: [
        // No external dependencies - uses only Apple frameworks
    ],

    targets: [
        // Main System Extension target
        .executableTarget(
            name: "TamanduaFileMonitor",
            dependencies: [],
            path: "TamanduaFileMonitor",
            exclude: [
                "Info.plist",
                "entitlements.plist"
            ],
            sources: [
                "TamanduaFileMonitor.swift",
                "ESClient.swift",
                "XPCServer.swift"
            ],
            swiftSettings: [
                // Enable strict concurrency checking
                .unsafeFlags(["-strict-concurrency=complete"]),
            ],
            linkerSettings: [
                // Link required Apple frameworks
                .linkedFramework("Foundation"),
                .linkedFramework("EndpointSecurity"),
                .linkedFramework("SystemExtensions"),
            ]
        ),

        // Unit tests for the System Extension
        .testTarget(
            name: "TamanduaFileMonitorTests",
            dependencies: ["TamanduaFileMonitor"],
            path: "Tests",
            sources: [
                "ESClientTests.swift",
                "XPCServerTests.swift"
            ]
        ),
    ]
)
