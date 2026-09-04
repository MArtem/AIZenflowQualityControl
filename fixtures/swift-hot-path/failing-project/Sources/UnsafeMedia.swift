import Foundation
import PDFKit
import UIKit

struct UnsafeMedia {
    func read(_ url: URL) -> Data {
        Data(contentsOf: url)
    }

    func image(_ path: String) -> UIImage? {
        UIImage(contentsOfFile: path)
    }

    func document(_ url: URL) -> PDFDocument? {
        PDFDocument(url: url)
    }
}
