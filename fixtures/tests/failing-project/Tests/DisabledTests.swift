import XCTest
import Testing

final class DisabledTests: XCTestCase {
    func testDisabled() throws {
        throw XCTSkip("fixture intentionally disabled")
    }
}

@Test(.disabled("fixture intentionally disabled"))
func disabledSwiftTestingFixture() {}
