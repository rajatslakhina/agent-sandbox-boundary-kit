/// One call the model asked for.
public struct ToolCall: Hashable, Sendable {
    public let id: String
    public let tool: String
    public let arguments: [String: String]

    public init(id: String, tool: String, arguments: [String: String] = [:]) {
        self.id = id
        self.tool = tool
        self.arguments = arguments
    }
}

/// A tool the agent can call. A tool declares the resources a call will touch
/// BEFORE it runs; the runtime judges that declaration, and only then calls `run`.
/// Anything else the tool needs mid-run must go through `context.authorize(_:)`.
///
/// This is enforcement by API, not by the kernel: Swift cannot stop a tool body
/// from calling `FileManager` directly. Tools are your code, reviewed like any
/// other privileged code; the process sandbox iOS already gives the app remains
/// the outer wall. See the README's limits.
public protocol SandboxTool: Sendable {
    var name: String { get }
    var summary: String { get }
    func declaredResources(for arguments: [String: String]) throws -> [Resource]
    func run(_ arguments: [String: String], context: ToolContext) async throws -> String
}

public enum ToolArgumentError: Error, Equatable, Sendable, CustomStringConvertible {
    case missing(String)

    public var description: String {
        switch self {
        case let .missing(key): return "missing argument '\(key)'"
        }
    }
}

/// A tool built from two closures. Handy for apps and tests alike.
public struct DeclarativeTool: SandboxTool {
    public let name: String
    public let summary: String
    private let resources: @Sendable ([String: String]) throws -> [Resource]
    private let body: @Sendable ([String: String], ToolContext) async throws -> String

    public init(
        name: String,
        summary: String,
        resources: @escaping @Sendable ([String: String]) throws -> [Resource],
        body: @escaping @Sendable ([String: String], ToolContext) async throws -> String
    ) {
        self.name = name
        self.summary = summary
        self.resources = resources
        self.body = body
    }

    public func declaredResources(for arguments: [String: String]) throws -> [Resource] {
        try resources(arguments)
    }

    public func run(_ arguments: [String: String], context: ToolContext) async throws -> String {
        try await body(arguments, context)
    }

    /// The value for `key`, or `ToolArgumentError.missing`.
    public static func require(_ key: String, in arguments: [String: String]) throws -> String {
        guard let value = arguments[key] else { throw ToolArgumentError.missing(key) }
        return value
    }
}

/// Thrown by `ToolContext.authorize(_:)` when a mid-run access is refused.
public struct SandboxDenial: Error, Equatable, Sendable {
    public let reason: DenialReason
}

/// Handed to a running tool. The only way for a tool to widen what it touches
/// after the gate has judged its declaration.
public struct ToolContext: Sendable {
    public let callID: String
    public let toolName: String
    let runToken: UInt64
    let runtime: ToolRuntime

    /// Judged by the deterministic rules against the manifest as it is NOW (not as
    /// it was when the call started), and counted toward lockout if denied.
    /// Review-flagged accesses are denied here: review is offered only up front.
    /// Calling this after the tool's call has returned is refused (`.callNotActive`).
    public func authorize(_ resource: Resource) async throws {
        try await runtime.authorizeDuringRun(resource, callID: callID, toolName: toolName, runToken: runToken)
    }
}
