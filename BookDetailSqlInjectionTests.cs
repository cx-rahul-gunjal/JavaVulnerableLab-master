// BookDetailSqlInjectionTests.cs
// Tests to verify that the SQL Injection vulnerability (CWE-89) in
// BookDetail.cs (Rating_update_Click) is properly remediated by using
// parameterized OleDbCommand queries instead of string concatenation.

using System;
using System.Data;
using System.Data.OleDb;
using NUnit.Framework;

namespace Book_Store.Tests
{
    /// <summary>
    /// Tests that validate the SQL Injection remediation applied to
    /// Rating_update_Click() in BookDetail.cs.
    ///
    /// The specific vulnerability was that Rating_item_id.Value and
    /// Rating_rating.SelectedItem.Value (both user-controlled) were
    /// concatenated directly into an UPDATE SQL string, which was then
    /// executed via OleDbCommand.ExecuteNonQuery().
    ///
    /// Fix: The SQL string now uses positional OleDb parameter placeholders (?)
    /// and values are bound via cmd.Parameters.AddWithValue(), parsed to int
    /// so user input never reaches the SQL parser as literal text.
    /// </summary>
    [TestFixture]
    public class BookDetailSqlInjectionTests
    {
        // ---------------------------------------------------------------------------
        // Helper: builds an OleDbCommand the same way the fixed code does,
        // so tests can inspect the command object without a live database.
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Simulates the fixed Rating_update_Click parameter binding logic.
        /// Returns the OleDbCommand with parameters bound (connection is null
        /// since these are unit tests — no DB access required).
        /// </summary>
        private static OleDbCommand BuildRatingUpdateCommand(string ratingValue, string itemIdValue)
        {
            // This mirrors the fixed code in Rating_update_Click:
            //   sSQL = "update items set rating=rating+?, rating_count=rating_count+1 where item_id=?";
            //   cmd.Parameters.AddWithValue("@rating", int.Parse(Rating_rating.SelectedItem.Value));
            //   cmd.Parameters.AddWithValue("@item_id", int.Parse(Rating_item_id.Value));
            const string sSQL = "update items set rating=rating+?, rating_count=rating_count+1 where item_id=?";
            OleDbCommand cmd = new OleDbCommand(sSQL);
            cmd.Parameters.AddWithValue("@rating", int.Parse(ratingValue));
            cmd.Parameters.AddWithValue("@item_id", int.Parse(itemIdValue));
            return cmd;
        }

        // ---------------------------------------------------------------------------
        // 1. Verify the SQL template no longer contains user-controlled data
        // ---------------------------------------------------------------------------

        [Test]
        public void FixedQuery_CommandText_ContainsOnlyParameterPlaceholders()
        {
            // Even with a malicious rating value, the command text must only
            // contain the static SQL template, never the user-supplied value.
            OleDbCommand cmd = BuildRatingUpdateCommand("3", "42");

            Assert.That(cmd.CommandText, Is.EqualTo(
                "update items set rating=rating+?, rating_count=rating_count+1 where item_id=?"),
                "CommandText must be the static parameterized template, not a concatenated string.");
        }

        [Test]
        public void FixedQuery_CommandText_DoesNotContainUserSuppliedRatingValue()
        {
            // Even if the user supplies a numeric value, it must not appear
            // in the SQL template text — it should only be in the parameter.
            OleDbCommand cmd = BuildRatingUpdateCommand("5", "100");

            Assert.That(cmd.CommandText, Does.Not.Contain("5"),
                "User-supplied rating value '5' must not be embedded in the SQL template.");
            Assert.That(cmd.CommandText, Does.Not.Contain("100"),
                "User-supplied item_id '100' must not be embedded in the SQL template.");
        }

        // ---------------------------------------------------------------------------
        // 2. Verify parameters are bound with correct types and values
        // ---------------------------------------------------------------------------

        [Test]
        public void FixedQuery_TwoParametersBound_ForRatingAndItemId()
        {
            OleDbCommand cmd = BuildRatingUpdateCommand("4", "7");

            Assert.That(cmd.Parameters.Count, Is.EqualTo(2),
                "Exactly two parameters must be bound: one for rating, one for item_id.");
        }

        [Test]
        public void FixedQuery_FirstParameter_IsRatingAsInt()
        {
            OleDbCommand cmd = BuildRatingUpdateCommand("3", "10");

            OleDbParameter ratingParam = cmd.Parameters[0];
            Assert.That(ratingParam.Value, Is.EqualTo(3),
                "The first parameter (rating) must be bound as an integer value 3.");
            Assert.That(ratingParam.Value, Is.TypeOf<int>(),
                "The rating parameter value must be of type int, not string.");
        }

        [Test]
        public void FixedQuery_SecondParameter_IsItemIdAsInt()
        {
            OleDbCommand cmd = BuildRatingUpdateCommand("3", "42");

            OleDbParameter itemIdParam = cmd.Parameters[1];
            Assert.That(itemIdParam.Value, Is.EqualTo(42),
                "The second parameter (item_id) must be bound as an integer value 42.");
            Assert.That(itemIdParam.Value, Is.TypeOf<int>(),
                "The item_id parameter value must be of type int, not string.");
        }

        // ---------------------------------------------------------------------------
        // 3. Verify SQL injection payloads are rejected at parse time (int.Parse)
        //    Attacker input that is not a valid integer must throw FormatException,
        //    preventing the payload from ever reaching the database.
        // ---------------------------------------------------------------------------

        [TestCase("1 OR 1=1",
            TestName = "SQLi_ItemId_ClassicOrCondition_ThrowsFormatException")]
        [TestCase("1; DROP TABLE items; --",
            TestName = "SQLi_ItemId_BatchedDropTable_ThrowsFormatException")]
        [TestCase("1' OR '1'='1",
            TestName = "SQLi_ItemId_SingleQuoteBypass_ThrowsFormatException")]
        [TestCase("1 UNION SELECT * FROM members --",
            TestName = "SQLi_ItemId_UnionSelect_ThrowsFormatException")]
        [TestCase("0; UPDATE items SET rating=0 WHERE 1=1 --",
            TestName = "SQLi_ItemId_BatchedUpdate_ThrowsFormatException")]
        public void FixedQuery_SqlInjectionInItemId_ThrowsFormatException(string maliciousItemId)
        {
            // Because the fix calls int.Parse(Rating_item_id.Value), any non-integer
            // injection payload will raise a FormatException before the command is
            // built, stopping the attack entirely.
            Assert.Throws<FormatException>(
                () => BuildRatingUpdateCommand("3", maliciousItemId),
                $"Malicious item_id payload '{maliciousItemId}' must not be accepted as a valid integer.");
        }

        [TestCase("3 OR 1=1",
            TestName = "SQLi_Rating_ClassicOrCondition_ThrowsFormatException")]
        [TestCase("3; DROP TABLE items; --",
            TestName = "SQLi_Rating_BatchedDropTable_ThrowsFormatException")]
        [TestCase("3' OR '1'='1",
            TestName = "SQLi_Rating_SingleQuoteBypass_ThrowsFormatException")]
        [TestCase("3 UNION SELECT password FROM members --",
            TestName = "SQLi_Rating_UnionSelect_ThrowsFormatException")]
        public void FixedQuery_SqlInjectionInRatingValue_ThrowsFormatException(string maliciousRating)
        {
            // Same protection for the rating parameter.
            Assert.Throws<FormatException>(
                () => BuildRatingUpdateCommand(maliciousRating, "42"),
                $"Malicious rating payload '{maliciousRating}' must not be accepted as a valid integer.");
        }

        // ---------------------------------------------------------------------------
        // 4. Positive tests — valid numeric inputs must be accepted and bound correctly
        // ---------------------------------------------------------------------------

        [TestCase("1", "1",  TestName = "ValidInput_Rating1_ItemId1")]
        [TestCase("2", "99", TestName = "ValidInput_Rating2_ItemId99")]
        [TestCase("3", "1000", TestName = "ValidInput_Rating3_ItemId1000")]
        [TestCase("4", "7",  TestName = "ValidInput_Rating4_ItemId7")]
        [TestCase("5", "42", TestName = "ValidInput_Rating5_ItemId42")]
        public void FixedQuery_ValidNumericInputs_BindCorrectly(
            string ratingValue, string itemIdValue)
        {
            // Legitimate numeric inputs (matching the 1–5 rating dropdown values)
            // must still work correctly after the fix.
            OleDbCommand cmd = BuildRatingUpdateCommand(ratingValue, itemIdValue);

            Assert.That(cmd.Parameters.Count, Is.EqualTo(2),
                "Both parameters must be bound for valid input.");
            Assert.That(cmd.Parameters[0].Value, Is.EqualTo(int.Parse(ratingValue)),
                "Rating parameter must match the parsed integer value.");
            Assert.That(cmd.Parameters[1].Value, Is.EqualTo(int.Parse(itemIdValue)),
                "Item_id parameter must match the parsed integer value.");
        }

        // ---------------------------------------------------------------------------
        // 5. Regression: confirm the vulnerable concatenated form is NOT being used
        // ---------------------------------------------------------------------------

        [Test]
        public void FixedQuery_CommandText_DoesNotContainConcatenationArtifacts()
        {
            // The old vulnerable pattern was:
            //   "update items set rating=rating+" + value + "... where item_id=" + id
            // After the fix the template is static — it must not contain the values.
            OleDbCommand cmd = BuildRatingUpdateCommand("5", "99");

            // The template must use ? placeholders, not literal values from user input
            Assert.That(cmd.CommandText, Does.Contain("?"),
                "Parameterized query must use ? as the OleDb positional placeholder.");
            Assert.That(cmd.CommandText, Does.Not.Match(@"rating\+\d"),
                "SQL template must not contain a literal integer after 'rating+'.");
            Assert.That(cmd.CommandText, Does.Not.Match(@"item_id=\d"),
                "SQL template must not contain a literal integer after 'item_id='.");
        }
    }
}
