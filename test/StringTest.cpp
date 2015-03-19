/*
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
#include <no/nostring.h>

// GTest uses this function to output objects
static void PrintTo(const NoString& s, std::ostream* o)
{
    *o << '"' << s.Escape_n(No::AsciiFormat, No::DebugFormat) << '"';
}

class EscapeTest : public ::testing::Test
{
protected:
    void testEncode(const NoString& in, const NoString& expectedOut, const NoString& sformat)
    {
        No::EscapeFormat format = NoString::ToEscape(sformat);
        NoString out;

        SCOPED_TRACE("Format: " + sformat);

        // Encode, then decode again and check we still got the same string
        out = in.Escape_n(No::AsciiFormat, format);
        EXPECT_EQ(expectedOut, out);
        out = out.Escape_n(format, No::AsciiFormat);
        EXPECT_EQ(in, out);
    }

    void testString(const NoString& in, const NoString& url, const NoString& html, const NoString& sql, const NoString& tag)
    {
        SCOPED_TRACE("String: " + in);

        testEncode(in, url, "URL");
        testEncode(in, html, "HTML");
        testEncode(in, sql, "SQL");
        testEncode(in, tag, "MSGTAG");
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
    EXPECT_EQ(true, NoString(true).ToBool());
    EXPECT_EQ(false, NoString(false).ToBool());
}

#define CS(s) (NoString((s), sizeof(s) - 1))

TEST(StringTest, Cmp)
{
    NoString s = "Bbb";

    EXPECT_EQ(NoString("Bbb"), s);
    EXPECT_LT(NoString("Aaa"), s);
    EXPECT_GT(NoString("Ccc"), s);
    EXPECT_EQ(0, s.Compare("Bbb", No::CaseSensitive));
    EXPECT_GT(0, s.Compare("bbb", No::CaseSensitive));
    EXPECT_LT(0, s.Compare("Aaa", No::CaseSensitive));
    EXPECT_GT(0, s.Compare("Ccc", No::CaseSensitive));
    EXPECT_EQ(0, s.Compare("Bbb", No::CaseInsensitive));
    EXPECT_EQ(0, s.Compare("bbb", No::CaseInsensitive));
    EXPECT_LT(0, s.Compare("Aaa", No::CaseInsensitive));
    EXPECT_GT(0, s.Compare("Ccc", No::CaseInsensitive));

    EXPECT_TRUE(s.Equals("bbb"));
    EXPECT_FALSE(s.Equals("bbb", No::CaseSensitive));
    EXPECT_FALSE(s.Equals("bb"));
}

TEST(StringTest, Wild)
{
    EXPECT_TRUE(NoString("").WildCmp("", No::CaseSensitive));
    EXPECT_TRUE(NoString("").WildCmp("", No::CaseInsensitive));

    EXPECT_FALSE(NoString("xy").WildCmp("*a*b*c*", No::CaseSensitive));
    EXPECT_FALSE(NoString("xy").WildCmp("*a*b*c*", No::CaseInsensitive));

    EXPECT_TRUE(NoString("I_am!~bar@foo").WildCmp("*!?bar@foo", No::CaseSensitive));
    EXPECT_TRUE(NoString("I_am!~bar@foo").WildCmp("*!?bar@foo", No::CaseInsensitive));

    EXPECT_FALSE(NoString("I_am!~bar@foo").WildCmp("*!?BAR@foo", No::CaseSensitive));
    EXPECT_TRUE(NoString("I_am!~bar@foo").WildCmp("*!?BAR@foo", No::CaseInsensitive));

    EXPECT_TRUE(NoString("abc").WildCmp("*a*b*c*", No::CaseSensitive));
    EXPECT_TRUE(NoString("abc").WildCmp("*a*b*c*", No::CaseInsensitive));

    EXPECT_FALSE(NoString("abc").WildCmp("*A*b*c*", No::CaseSensitive));
    EXPECT_TRUE(NoString("abc").WildCmp("*A*b*c*", No::CaseInsensitive));

    EXPECT_FALSE(NoString("Abc").WildCmp("*a*b*c*", No::CaseSensitive));
    EXPECT_TRUE(NoString("Abc").WildCmp("*a*b*c*", No::CaseInsensitive));

    EXPECT_TRUE(NoString("axbyc").WildCmp("*a*b*c*", No::CaseSensitive));
    EXPECT_TRUE(NoString("axbyc").WildCmp("*a*b*c*", No::CaseInsensitive));

    EXPECT_FALSE(NoString("AxByC").WildCmp("*a*B*c*", No::CaseSensitive));
    EXPECT_TRUE(NoString("AxByC").WildCmp("*a*B*c*", No::CaseInsensitive));
}

TEST(StringTest, Case)
{
    NoString x = CS("xx");
    NoString X = CS("XX");
    EXPECT_EQ(X, x.AsUpper());
    EXPECT_EQ(x, X.AsLower());
}

TEST(StringTest, Replace)
{
    EXPECT_EQ("(b()b)", NoString("(a()a)").Replace_n("a", "b"));
    EXPECT_EQ("(a()b)", NoString("(a()a)").Replace_n("a", "b", "(", ")"));
    EXPECT_EQ("a(b)", NoString("(a()a)").Replace_n("a", "b", "(", ")", true));
}

TEST(StringTest, LeftRight)
{
    EXPECT_EQ("Xy", CS("Xyz").Left(2));
    EXPECT_EQ("Xyz", CS("Xyz").Left(20));

    EXPECT_EQ("yz", CS("Xyz").Right(2));
    EXPECT_EQ("Xyz", CS("Xyz").Right(20));
}

TEST(StringTest, Split)
{
    EXPECT_EQ("a", CS("a b c").Token(0));
    EXPECT_EQ("b", CS("a b c").Token(1));
    EXPECT_EQ("", CS("a b c").Token(100));
    EXPECT_EQ("b c", CS("a b c").Token(1, true));
    EXPECT_EQ("c", CS("a  c").Token(1));
    EXPECT_EQ("", CS("a  c").Token(1, false, " ", true));
    EXPECT_EQ("c", CS("a  c").Token(1, false, "  "));
    EXPECT_EQ(" c", CS("a   c").Token(1, false, "  "));
    EXPECT_EQ("c", CS("a    c").Token(1, false, "  "));
    EXPECT_EQ("b c", CS("a (b c) d").Token(1, false, " ", false, "(", ")"));
    EXPECT_EQ("(b c)", CS("a (b c) d").Token(1, false, " ", false, "(", ")", false));
    EXPECT_EQ("d", CS("a (b c) d").Token(2, false, " ", false, "(", ")", false));

    NoStringVector vexpected;
    vexpected.push_back("a");
    vexpected.push_back("b");
    vexpected.push_back("c");
    NoStringVector vresult = CS("a b c").Split(" ");
    EXPECT_EQ(vexpected, vresult);
}

TEST(StringTest, Equals)
{
    EXPECT_TRUE(CS("ABC").Equals("abc"));
    EXPECT_TRUE(CS("ABC").Equals("abc", No::CaseInsensitive));
    EXPECT_FALSE(CS("ABC").Equals("abc", No::CaseSensitive));
}

TEST(StringTest, Find)
{
    EXPECT_EQ(NoString("Hello, I'm Bob").Find("Hello"), 0u);
    EXPECT_EQ(NoString("Hello, I'm Bob").Find("Hello", No::CaseInsensitive), 0u);
    EXPECT_EQ(NoString("Hello, I'm Bob").Find("Hello", No::CaseSensitive), 0u);

    EXPECT_EQ(NoString("Hello, I'm Bob").Find("i'm"), 7u);
    EXPECT_EQ(NoString("Hello, I'm Bob").Find("i'm", No::CaseInsensitive), 7u);
    EXPECT_EQ(NoString("Hello, I'm Bob").Find("i'm", No::CaseSensitive), NoString::npos);
}

TEST(StringTest, StartsWith)
{
    EXPECT_TRUE(NoString("Hello, I'm Bob").StartsWith("Hello"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").StartsWith("Hello", No::CaseInsensitive));
    EXPECT_TRUE(NoString("Hello, I'm Bob").StartsWith("Hello", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").StartsWith("hello"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").StartsWith("hello", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").StartsWith("hello", No::CaseSensitive));
}

TEST(StringTest, EndsWith)
{
    EXPECT_TRUE(NoString("Hello, I'm Bob").EndsWith("Bob"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").EndsWith("Bob", No::CaseInsensitive));
    EXPECT_TRUE(NoString("Hello, I'm Bob").EndsWith("Bob", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").EndsWith("bob"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").EndsWith("bob", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").EndsWith("bob", No::CaseSensitive));
}

TEST(StringTest, Contains)
{
    EXPECT_TRUE(NoString("Hello, I'm Bob").Contains("Hello"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").Contains("Hello", No::CaseInsensitive));
    EXPECT_TRUE(NoString("Hello, I'm Bob").Contains("Hello", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").Contains("i'm"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").Contains("i'm", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").Contains("i'm", No::CaseSensitive));

    EXPECT_TRUE(NoString("Hello, I'm Bob").Contains("i'm bob"));
    EXPECT_TRUE(NoString("Hello, I'm Bob").Contains("i'm bob", No::CaseInsensitive));
    EXPECT_FALSE(NoString("Hello, I'm Bob").Contains("i'm bob", No::CaseSensitive));
}
