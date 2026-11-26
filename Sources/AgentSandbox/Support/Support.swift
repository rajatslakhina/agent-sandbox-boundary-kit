// Small, dependency-free helpers shared by the rest of the module.

extension Int {
    /// Addition that clamps at `Int.max` / `Int.min` instead of trapping.
    /// Counters in this module (denials, dropped log entries) use it so that no
    /// public entry point can overflow-trap, however long a session runs.
    func saturatingAdd(_ other: Int) -> Int {
        let (result, overflow) = addingReportingOverflow(other)
        guard overflow else { return result }
        return other > 0 ? .max : .min
    }

    /// Multiplication that clamps instead of trapping.
    func saturatingMultiply(_ other: Int) -> Int {
        let (result, overflow) = multipliedReportingOverflow(by: other)
        guard overflow else { return result }
        return (self < 0) == (other < 0) ? .max : .min
    }
}

extension String {
    /// The first `limit` Unicode scalars. A non-positive limit yields "".
    /// Scalars, not grapheme clusters: one cluster can be megabytes of combining
    /// marks, so only a scalar (or byte) count actually bounds memory.
    func clamped(to limit: Int) -> String {
        guard limit > 0 else { return "" }
        return String(String.UnicodeScalarView(unicodeScalars.prefix(limit)))
    }
}

/// 64-bit FNV-1a. Deliberately not `Hasher`: `Hasher` is randomly seeded per
/// process, so it cannot produce a digest that is stable across launches, devices
/// or the prompt-vs-policy comparison this module exists to make.
///
/// FNV-1a is NOT cryptographic. The manifest digest detects drift between the
/// prompt and the enforced policy; it does not defend against a forger.
struct FNV1a64 {
    private(set) var value: UInt64 = 0xcbf2_9ce4_8422_2325

    mutating func combine(byte: UInt8) {
        value ^= UInt64(byte)
        value = value &* 0x0000_0100_0000_01b3 // wrapping multiply is the algorithm
    }

    /// Length-prefixed, so ("ab","c") and ("a","bc") hash differently.
    mutating func combine(_ string: String) {
        let bytes = Array(string.utf8)
        combine(count: bytes.count)
        for byte in bytes { combine(byte: byte) }
    }

    mutating func combine(count: Int) {
        var v = UInt64(clamping: count)
        for _ in 0..<8 {
            combine(byte: UInt8(truncatingIfNeeded: v))
            v >>= 8
        }
    }

    var hex: String {
        let digits = String(value, radix: 16)
        return String(repeating: "0", count: max(0, 16 - digits.count)) + digits
    }
}

/// A fixed-capacity log that overwrites its oldest entry when full and counts
/// what it dropped, so memory stays bounded for a session of any length.
struct BoundedLog<Element: Sendable>: Sendable {
    let capacity: Int
    private var storage: [Element] = []
    private var head = 0
    private(set) var dropped = 0

    init(capacity: Int) {
        self.capacity = Swift.max(1, capacity)
    }

    mutating func append(_ element: Element) {
        if storage.count < capacity {
            storage.append(element)
        } else {
            // Full: storage.count == capacity >= 1, and head is always in 0..<capacity.
            storage[head] = element
            head = (head + 1) % capacity
            dropped = dropped.saturatingAdd(1)
        }
    }

    /// Oldest first.
    var elements: [Element] {
        guard head > 0 else { return storage }
        return Array(storage[head...]) + Array(storage[..<head])
    }
}
