import Foundation
import Security

/// Reads the CodeDirectory hash macOS associates with a running process.
///
/// The caller supplies the expected value from its trusted workflow. This helper never derives
/// that expectation from a mutable executable path or source checkout.
enum ProcessCodeIdentity {
    static func currentCodeDirectoryHash() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess,
              let code else {
            return nil
        }
        return codeDirectoryHash(for: code)
    }

    static func codeDirectoryHash(forProcessIdentifier processIdentifier: pid_t) -> String? {
        guard processIdentifier > 0 else {
            return nil
        }
        let attributes: NSDictionary = [
            kSecGuestAttributePid: NSNumber(value: processIdentifier)
        ]
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else {
            return nil
        }
        return codeDirectoryHash(for: code)
    }

    private static func codeDirectoryHash(for code: SecCode) -> String? {
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return nil
        }
        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInformation
        ) == errSecSuccess,
        let signingInformation,
        let data = (signingInformation as NSDictionary)[kSecCodeInfoUnique] as? Data,
        data.count == 20 else {
            return nil
        }
        return data.map { String(format: "%02x", $0) }.joined()
    }
}
