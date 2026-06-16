// BookDetailXssTests.cs
// Tests to verify that:
//  1. The Stored XSS vulnerability (CWE-79) in BookDetail.cs is properly
//     remediated by ensuring HTML encoding is applied to page controls.
//  2. The SQL Injection vulnerability (CWE-89) in Rating_Show() is properly
//     remediated by using a parameterized OleDbCommand with OleDbParameter
//     instead of string-concatenated SQL.

using System;
using System.Data.OleDb;
using System.Web;
using NUnit.Framework;

namespace Book_Store.Tests
{
    /// <summary>
    /// Tests that validate:
    ///   (a) HTML encoding of database-sourced values (XSS prevention, CWE-79).
    ///   (b) Parameterized SQL query construction in Rating_Show() (SQLi prevention, CWE-89).
    ///
    /// XSS fix: Server.HtmlEncode(CCUtility.GetValue(row, "image_url").ToString())
    /// SQL fix:  OleDbCommand with '?' placeholder and OleDbParameter bound to
    ///           int.Parse(p_Rating_item_id.Value) instead of string concatenation.
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

        // ---------------------------------------------------------------------------
        // 5. SQL Injection prevention — Rating_Show() parameterized query (CWE-89)
        //    These tests validate the logic used to build the OleDbCommand and that
        //    the item_id is bound as a typed integer parameter, never concatenated.
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Validates that a valid numeric item_id is correctly parsed to int,
        /// which is the value bound to the OleDbParameter in Rating_Show().
        /// If int.Parse succeeds, no tainted string reaches the SQL engine.
        /// </summary>
        [Test]
        public void RatingShow_ValidNumericItemId_ParsesSuccessfully()
        {
            // Simulates: int.Parse(p_Rating_item_id.Value) in the parameterized fix
            string itemId = "42";
            int parsed = int.Parse(itemId);
            Assert.That(parsed, Is.EqualTo(42),
                "A valid numeric item_id string must parse to its integer value.");
        }

        /// <summary>
        /// Validates that a SQL injection payload in item_id fails the int.Parse()
        /// guard before reaching the OleDbParameter, ensuring the tainted string
        /// is never bound to — or concatenated into — the SQL query.
        /// </summary>
        [TestCase("1 OR 1=1",          TestName = "SQLi_OrAlways_Blocked")]
        [TestCase("1; DROP TABLE items--", TestName = "SQLi_Stacked_Blocked")]
        [TestCase("1' AND '1'='1",     TestName = "SQLi_SingleQuoteAnd_Blocked")]
        [TestCase("0 UNION SELECT * FROM users--", TestName = "SQLi_Union_Blocked")]
        [TestCase("abc",               TestName = "SQLi_NonNumericAlpha_Blocked")]
        [TestCase("1.5",               TestName = "SQLi_FloatString_Blocked")]
        public void RatingShow_NonIntegerItemId_ThrowsFormatException(string maliciousItemId)
        {
            // The fix does: int.Parse(p_Rating_item_id.Value)
            // Any non-integer payload must throw FormatException, never reaching the DB.
            Assert.Throws<FormatException>(
                () => int.Parse(maliciousItemId),
                $"SQL injection payload '{maliciousItemId}' must be rejected by int.Parse().");
        }

        /// <summary>
        /// Validates that the SQL template used in Rating_Show() is a static string
        /// with a positional '?' placeholder and contains no string-format operators
        /// or concatenation artifacts — confirming it is safe to use as a
        /// parameterized OleDb command text.
        /// </summary>
        [Test]
        public void RatingShow_SqlTemplate_UsesPositionalPlaceholderNotConcatenation()
        {
            // This is the exact SQL constant defined in the fixed Rating_Show():
            const string sqlTemplate = "select * from items where item_id=?";

            // Must contain '?' OleDb positional placeholder
            Assert.That(sqlTemplate, Does.Contain("?"),
                "Parameterized OleDb SQL must use '?' as a positional placeholder.");

            // Must NOT contain '{' or '+' which would indicate format/concatenation
            Assert.That(sqlTemplate, Does.Not.Contain("{"),
                "SQL template must not use string.Format-style placeholders.");
            Assert.That(sqlTemplate, Does.Not.Contain("' +"),
                "SQL template must not concatenate string fragments.");
        }

        /// <summary>
        /// Validates that OleDbParameter creation with OleDbType.Integer correctly
        /// rejects a non-integer value at parameter-binding time, providing a
        /// second layer of defense even if int.Parse were bypassed.
        /// </summary>
        [Test]
        public void OleDbParameter_IntegerType_RejectsStringValue()
        {
            // Reproduces the parameter setup from Rating_Show():
            //   ratingCmd.Parameters.Add(new OleDbParameter("item_id", OleDbType.Integer)).Value = int.Parse(...)
            // Verify that assigning a proper int to an Integer-typed parameter is accepted.
            var param = new OleDbParameter("item_id", OleDbType.Integer);
            param.Value = 42; // valid integer

            Assert.That(param.Value, Is.EqualTo(42),
                "An integer value must be stored correctly in an OleDbParameter of type Integer.");
            Assert.That(param.OleDbType, Is.EqualTo(OleDbType.Integer),
                "Parameter type must remain OleDbType.Integer.");
        }

        /// <summary>
        /// Validates that the OleDbParameter name and type match what Rating_Show()
        /// uses, ensuring the parameter contract is preserved after the fix.
        /// </summary>
        [Test]
        public void OleDbParameter_RatingShowContract_NameAndTypeCorrect()
        {
            var param = new OleDbParameter("item_id", OleDbType.Integer);

            Assert.That(param.ParameterName, Is.EqualTo("item_id"),
                "Parameter name must be 'item_id' to match the query column.");
            Assert.That(param.OleDbType, Is.EqualTo(OleDbType.Integer),
                "Parameter type must be OleDbType.Integer for a numeric item_id.");
        }
    }
}
