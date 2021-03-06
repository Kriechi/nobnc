/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <nobnc/nostring.h>
#include <nobnc/noutils.h>

// GTest uses this function to output objects
static void PrintTo(const NoString& s, std::ostream* o)
{
    *o << '"' << No::escape(s, No::AsciiFormat, No::DebugFormat) << '"';
}

class EscapeTest : public ::testing::Test
{
protected:
    void testEncode(const NoString& in, const NoString& expectedOut, No::EscapeFormat format)
    {
        // Encode, then decode again and check we still got the same string
        NoString out = No::escape(in, No::AsciiFormat, format);
        EXPECT_EQ(expectedOut, out);
        out = No::escape(out, format, No::AsciiFormat);
        EXPECT_EQ(in, out);
    }

    void testString(const NoString& in, const NoString& url, const NoString& html, const NoString& sql, const NoString& tag)
    {
        SCOPED_TRACE("String: " + in);

        testEncode(in, url, No::UrlFormat);
        testEncode(in, html, No::HtmlFormat);
        testEncode(in, sql, No::SqlFormat);
        testEncode(in, tag, No::MsgTagFormat);
    }
};

TEST_F(EscapeTest, Test)
{
    //          input     url          html             sql         msgtag
    testString("abcdefg", "abcdefg", "abcdefg", "abcdefg", "abcdefg");
    testString("\n\t\r", "%0A%09%0D", "\n\t\r", "\\n\\t\\r", "\\n\t\\r");
    testString("'\"", "%27%22", "'&quot;", "\\'\\\"", "'\"");
    testString("&<>", "%26%3C%3E", "&amp;&lt;&gt;", "&<>", "&<>");
    testString(" ;", "+%3B", " ;", " ;", "\\s\\:");
}

TEST(StringTest, Bool)
{
    EXPECT_EQ(true, NoString(true).toBool());
    EXPECT_EQ(false, NoString(false).toBool());
}

#define NS(s) (NoString((s), sizeof(s) - 1))

TEST(StringTest, Cmp)
{
    NoString s = "Bbb";

    EXPECT_EQ(NoString("Bbb"), s);
    EXPECT_LT(NoString("Aaa"), s);
    EXPECT_GT(NoString("Ccc"), s);
    EXPECT_EQ(0, s.compare("Bbb", No::CaseSensitive));
    EXPECT_GT(0, s.compare("bbb", No::CaseSensitive));
    EXPECT_LT(0, s.compare("Aaa", No::CaseSensitive));
    EXPECT_GT(0, s.compare("Ccc", No::CaseSensitive));
    EXPECT_EQ(0, s.compare("Bbb", No::CaseInsensitive));
    EXPECT_EQ(0, s.compare("bbb", No::CaseInsensitive));
    EXPECT_LT(0, s.compare("Aaa", No::CaseInsensitive));
    EXPECT_GT(0, s.compare("Ccc", No::CaseInsensitive));

    EXPECT_TRUE(s.equals("bbb"));
    EXPECT_FALSE(s.equals("bbb", No::CaseSensitive));
    EXPECT_FALSE(s.equals("bb"));
}

TEST(StringTest, Case)
{
    NoString x = NS("xx");
    NoString X = NS("XX");
    EXPECT_EQ(X, x.toUpper());
    EXPECT_EQ(x, X.toLower());
}

TEST(StringTest, Replace)
{
    EXPECT_EQ("(b()b)", NoString("(a()a)").replace_n("a", "b"));
    //    EXPECT_EQ("(a()b)", NoString("(a()a)").Replace_n("a", "b", "(", ")"));
    //    EXPECT_EQ("a(b)", NoString("(a()a)").Replace_n("a", "b", "(", ")", true));
}

TEST(StringTest, LeftRight)
{
    EXPECT_EQ("Xy", NS("Xyz").left(2));
    EXPECT_EQ("Xyz", NS("Xyz").left(20));

    EXPECT_EQ("yz", NS("Xyz").right(2));
    EXPECT_EQ("Xyz", NS("Xyz").right(20));
}

TEST(StringTest, Split)
{
    NoStringVector vexpected;
    vexpected.push_back("a");
    vexpected.push_back("b");
    vexpected.push_back("c");
    NoStringVector vresult = NS("a b c").split(" ");
    EXPECT_EQ(vexpected, vresult);
}

TEST(StringTest, Equals)
{
    EXPECT_TRUE(NS("ABC").equals("abc"));
    EXPECT_TRUE(NS("ABC").equals("abc", No::CaseInsensitive));
    EXPECT_FALSE(NS("ABC").equals("abc", No::CaseSensitive));
}

TEST(StringTest, Find)
{
    EXPECT_EQ(NoString("Hello, I'm Bob").find("Hello"), 0u);
    EXPECT_EQ(NoString("Hello, I'm Bob").find("Hello", No::CaseInsensitive), 0u);
    EXPECT_EQ(NoString("Hello, I'm Bob").find("Hello", No::CaseSensitive), 0u);

    EXPECT_EQ(NoString("Hello, I'm Bob").find("i'm"), 7u);
    EXPECT_EQ(NoString("Hello, I'm Bob").find("i'm", No::CaseInsensitive), 7u);
    EXPECT_EQ(NoString("Hello, I'm Bob").find("i'm", No::CaseSensitive), NoString::npos);
}

TEST(StringTest, StartsWith)
{
    EXPECT_TRUE(NoString("Hello, I'm Bob").startsWith("Hello"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").startsWith("Hello", No::CaseInsensitive));
    EXPECT_TRUE(NoString("Hello, I'm Bob").startsWith("Hello", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").startsWith("hello"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").startsWith("hello", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").startsWith("hello", No::CaseSensitive));
}

TEST(StringTest, EndsWith)
{
    EXPECT_TRUE(NoString("Hello, I'm Bob").endsWith("Bob"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").endsWith("Bob", No::CaseInsensitive));
    EXPECT_TRUE(NoString("Hello, I'm Bob").endsWith("Bob", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").endsWith("bob"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").endsWith("bob", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").endsWith("bob", No::CaseSensitive));
}

TEST(StringTest, Contains)
{
    EXPECT_TRUE(NoString("Hello, I'm Bob").contains("Hello"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").contains("Hello", No::CaseInsensitive));
    EXPECT_TRUE(NoString("Hello, I'm Bob").contains("Hello", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").contains("i'm"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").contains("i'm", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").contains("i'm", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").contains("i'm bob"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").contains("i'm bob", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").contains("i'm bob", No::CaseSensitive));
}
