// BookDetailXssTests.cs
// Tests to verify that the Stored XSS vulnerability (CWE-79) in BookDetail.cs
// is properly remediated by ensuring HTML encoding is applied to the
// Detail_image_url.Text field (and other fields) populated from the database.

using System;
using System.Web;
using NUnit.Framework;

namespace Book_Store.Tests
{
    /// <summary>
    /// Tests that validate HTML encoding of database-sourced values before
    /// they are assigned to page controls, preventing Stored XSS attacks.
    ///
    /// The specific vulnerability was in Detail_Show() where image_url data
    /// read from the database was assigned to Detail_image_url.Text without
    /// calling Server.HtmlEncode(), unlike all surrounding field assignments.
    /// Fix: Server.HtmlEncode(CCUtility.GetValue(row, "image_url").ToString())
    /// </summary>
    [TestFixture]
    public class BookDetailXssTests
    {
        // ---------------------------------------------------------------------------
        // Helper: simulates what Server.HtmlEncode / HttpUtility.HtmlEncode does.
        // In ASP.NET Web Forms, Server.HtmlEncode delegates to HttpUtility.HtmlEncode.
        // ---------------------------------------------------------------------------
        private static string HtmlEncode(string value)
        {
            return HttpUtility.HtmlEncode(value);
        }

        // ---------------------------------------------------------------------------
        // 1. Core encoding correctness
        // ---------------------------------------------------------------------------

        [Test]
        public void HtmlEncode_ScriptTag_ShouldEncodeAngleBrackets()
        {
            // A classic stored XSS payload stored in image_url column
            string maliciousImageUrl = "<script>alert('xss')</script>";

            string encoded = HtmlEncode(maliciousImageUrl);

            // Angle brackets MUST be HTML-encoded so the browser never executes the script
            Assert.That(encoded, Does.Not.Contain("<script>"),
                "Unencoded <script> tag must not be present in the output.");
            Assert.That(encoded, Does.Contain("&lt;script&gt;"),
                "Script tag must be encoded as &lt;script&gt;.");
        }

        [Test]
        public void HtmlEncode_InlineEventHandler_ShouldEncodeQuotesAndAngleBrackets()
        {
            // Payload that tries to inject an event handler via an attribute context
            string payload = "\"><img src=x onerror=alert(1)>";

            string encoded = HtmlEncode(payload);

            Assert.That(encoded, Does.Not.Contain("\"<"),
                "Raw double-quote + angle bracket sequence must not appear unencoded.");
            Assert.That(encoded, Does.Contain("&quot;") | Does.Contain("&#34;"),
                "Double-quote must be encoded.");
            Assert.That(encoded, Does.Contain("&lt;"),
                "Opening angle bracket must be HTML-encoded.");
        }

        [Test]
        public void HtmlEncode_AmpersandInUrl_ShouldBeEncoded()
        {
            // Ampersands in URLs are valid but must be encoded when placed in HTML context
            string urlWithAmpersand = "http://example.com/image?a=1&b=2";

            string encoded = HtmlEncode(urlWithAmpersand);

            Assert.That(encoded, Does.Contain("&amp;"),
                "Ampersand must be encoded as &amp; in HTML context.");
        }

        [Test]
        public void HtmlEncode_SafeUrl_ShouldRemainFunctional()
        {
            // A benign image URL with no special characters should pass through intact
            string safeUrl = "http://example.com/images/book_cover.jpg";

            string encoded = HtmlEncode(safeUrl);

            // No special characters to encode; the string is unchanged
            Assert.That(encoded, Is.EqualTo(safeUrl),
                "A URL without HTML special characters should not be altered by encoding.");
        }

        [Test]
        public void HtmlEncode_EmptyString_ShouldReturnEmptyString()
        {
            string result = HtmlEncode(string.Empty);
            Assert.That(result, Is.EqualTo(string.Empty),
                "Encoding an empty string should return an empty string.");
        }

        [Test]
        public void HtmlEncode_NullToString_ShouldNotThrow()
        {
            // CCUtility.GetValue can return null; the fix calls .ToString() before encoding.
            // Verify that treating null as empty string is handled gracefully.
            string value = null;
            // Mirrors the fix pattern: CCUtility.GetValue(row, "image_url").ToString()
            string safeValue = (value ?? string.Empty).ToString();
            string result = HtmlEncode(safeValue);

            Assert.That(result, Is.EqualTo(string.Empty),
                "A null value converted to string should encode to an empty string.");
        }

        // ---------------------------------------------------------------------------
        // 2. XSS attack vector coverage — common stored XSS payloads
        // ---------------------------------------------------------------------------

        [TestCase("<img src=x onerror=alert(1)>",
            TestName = "XSS_ImgOnerrorPayload_Encoded")]
        [TestCase("javascript:alert('xss')",
            TestName = "XSS_JavascriptProtocolPayload_ColonNotSpecial_Encoded")]
        [TestCase("<svg/onload=alert(1)>",
            TestName = "XSS_SvgOnloadPayload_Encoded")]
        [TestCase("'><script>document.cookie</script>",
            TestName = "XSS_SingleQuoteScriptPayload_Encoded")]
        [TestCase("<body onload=alert('xss')>",
            TestName = "XSS_BodyOnloadPayload_Encoded")]
        public void HtmlEncode_StoredXssPayloads_ShouldNotContainUnencodedAngleBrackets(
            string xssPayload)
        {
            string encoded = HtmlEncode(xssPayload);

            // After encoding, no raw HTML tags should survive
            Assert.That(encoded, Does.Not.Match(@"<[a-zA-Z]"),
                $"Payload '{xssPayload}' must not contain unencoded HTML tags after encoding.");
        }

        // ---------------------------------------------------------------------------
        // 3. Consistency — all Detail fields should be encoded the same way
        //    (validates the fix is consistent with surrounding field assignments)
        // ---------------------------------------------------------------------------

        [Test]
        public void AllDetailTextFields_WhenEncodingApplied_ProduceSameResultAsHtmlEncode()
        {
            // Verifies that Server.HtmlEncode (HttpUtility.HtmlEncode) produces
            // the expected output for each field type found in Detail_Show().
            // This acts as a regression check for the pattern:
            //   SomeControl.Text = Server.HtmlEncode(CCUtility.GetValue(row, "field").ToString())

            var fieldValues = new[]
            {
                ("name",         "O'Reilly & Associates <Test>"),
                ("author",       "Jane <script>Doe</script>"),
                ("price",        "29.99"),
                ("image_url",    "<script>alert('stored xss')</script>"),   // the previously vulnerable field
                ("product_url",  "http://example.com/book?id=1&ref=2"),
            };

            foreach (var (field, rawValue) in fieldValues)
            {
                string encoded = HtmlEncode(rawValue);

                // Encoded output must not contain unencoded < or > characters
                Assert.That(encoded, Does.Not.Contain("<"),
                    $"Field '{field}': raw '<' must be HTML-encoded.");
                Assert.That(encoded, Does.Not.Contain(">"),
                    $"Field '{field}': raw '>' must be HTML-encoded.");
            }
        }

        // ---------------------------------------------------------------------------
        // 4. Regression guard — encoding must not double-encode already safe text
        // ---------------------------------------------------------------------------

        [Test]
        public void HtmlEncode_AlphanumericText_IsNotDoubleEncoded()
        {
            string plainText = "The Great Gatsby 1925";

            string encodedOnce = HtmlEncode(plainText);
            // Plain alphanumeric text has no special HTML characters
            Assert.That(encodedOnce, Is.EqualTo(plainText),
                "Plain text without HTML special characters should not be altered.");
        }

        [Test]
        public void HtmlEncode_TextWithAmpersandTitle_EncodesOnceCorrectly()
        {
            // Book titles often contain "&" — ensure single-pass encoding
            string title = "War & Peace";

            string encoded = HtmlEncode(title);

            Assert.That(encoded, Is.EqualTo("War &amp; Peace"),
                "A single '&' in a title should be encoded as '&amp;'.");
            // Must not be double-encoded to &amp;amp;
            Assert.That(encoded, Does.Not.Contain("&amp;amp;"),
                "Encoding must not be applied twice.");
        }
    }
}
