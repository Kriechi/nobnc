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
#include <no/nofile.h>
#include <no/noutils.h>

TEST(UtilsTest, Hash)
{
    EXPECT_EQ("d41d8cd98f00b204e9800998ecf8427e", No::md5(""));
    EXPECT_EQ("0cc175b9c0f1b6a831c399e269772661", No::md5("a"));

    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", No::sha256(""));
    EXPECT_EQ("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", No::sha256("a"));
}

TEST(UtilsTest, GetMessageTags)
{
    EXPECT_EQ(NoStringMap(), No::messageTags(""));
    EXPECT_EQ(NoStringMap(), No::messageTags(":nick!ident@host PRIVMSG #chan :hello world"));

    NoStringMap exp;
    exp["a"] = "b";
    EXPECT_EQ(exp, No::messageTags("@a=b"));
    EXPECT_EQ(exp, No::messageTags("@a=b :nick!ident@host PRIVMSG #chan :hello world"));
    EXPECT_EQ(exp, No::messageTags("@a=b :rest"));
    exp.clear();

    exp["ab"] = "cdef";
    exp["znc.in/gh-ij"] = "klmn,op";
    EXPECT_EQ(exp, No::messageTags("@ab=cdef;znc.in/gh-ij=klmn,op :rest"));
    exp.clear();

    exp["a"] = "==b==";
    EXPECT_EQ(exp, No::messageTags("@a===b== :rest"));
    exp.clear();

    exp["a"] = "";
    exp["b"] = "c";
    exp["d"] = "";
    EXPECT_EQ(exp, No::messageTags("@a;b=c;d :rest"));
    exp.clear();

    exp["semi-colon"] += ';';
    exp["space"] += ' ';
    exp["NUL"] += '\0';
    exp["backslash"] += '\\';
    exp["CR"] += '\r';
    exp["LF"] += '\n';
    EXPECT_EQ(exp, No::messageTags(R"(@semi-colon=\:;space=\s;NUL=\0;backslash=\\;CR=\r;LF=\n :rest)"));
    exp.clear();

    exp["a"] = "; \\\r\n";
    EXPECT_EQ(exp, No::messageTags(R"(@a=\:\s\\\r\n :rest)"));
    exp.clear();
}

TEST(UtilsTest, SetMessageTags)
{
    NoString sLine;

    sLine = ":rest";
    No::setMessageTags(sLine, NoStringMap());
    EXPECT_EQ(":rest", sLine);

    NoStringMap tags;
    tags["a"] = "b";
    No::setMessageTags(sLine, tags);
    EXPECT_EQ("@a=b :rest", sLine);

    tags["c"] = "d";
    No::setMessageTags(sLine, tags);
    EXPECT_EQ("@a=b;c=d :rest", sLine);

    tags["e"] = "";
    No::setMessageTags(sLine, tags);
    EXPECT_EQ("@a=b;c=d;e :rest", sLine);
    tags.clear();

    tags["semi-colon"] += ';';
    tags["space"] += ' ';
    tags["NUL"] += '\0';
    tags["backslash"] += '\\';
    tags["CR"] += '\r';
    tags["LF"] += '\n';
    No::setMessageTags(sLine, tags);
    EXPECT_EQ(R"(@CR=\r;LF=\n;NUL=\0;backslash=\\;semi-colon=\:;space=\s :rest)", sLine);
    tags.clear();

    tags["a"] = "; \\\r\n";
    No::setMessageTags(sLine, tags);
    EXPECT_EQ(R"(@a=\:\s\\\r\n :rest)", sLine);
}

TEST(UtilsTest, NamedFormat)
{
    NoStringMap m;
    m["a"] = "b";
    EXPECT_EQ("{xbyb", No::namedFormat(NoString("\\{x{a}y{a}"), m));
}

TEST(UtilsTest, Ellipsize)
{
    EXPECT_EQ("Hello,...", No::ellipsize("Hello, I'm Bob", 9));
    EXPECT_EQ("Hello, I'm Bob", No::ellipsize("Hello, I'm Bob", 90));
    EXPECT_EQ("..", No::ellipsize("Hello, I'm Bob", 2));
}

TEST(UtilsTest, QuoteSplit)
{
    NoStringVector expected;

    expected = NoStringVector{"\"a  b  c\""};
    EXPECT_EQ(expected, No::quoteSplit("  \"a  b  c\"  "));

    expected = NoStringVector{"\"a b\"", "\"c d\""};
    EXPECT_EQ(expected, No::quoteSplit("\"a b\" \"c d\""));

    expected = NoStringVector{"a", "\"b c\"", "d"};
    EXPECT_EQ(expected, No::quoteSplit("a \"b c\" d"));

    expected = NoStringVector{"\" a \"", "\" b \""};
    EXPECT_EQ(expected, No::quoteSplit("\" a \" \" b \""));

    expected = NoStringVector{"\" \""};
    EXPECT_EQ(expected, No::quoteSplit("\" \""));

    expected = NoStringVector{ "\"\"" };
    EXPECT_EQ(expected, No::quoteSplit("\"\""));
}

TEST(UtilsTest, WildCmp)
{
    EXPECT_TRUE(No::wildCmp("", "", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("", "", No::CaseInsensitive));

    EXPECT_FALSE(No::wildCmp("xy", "*a*b*c*", No::CaseSensitive));
    EXPECT_FALSE(No::wildCmp("xy", "*a*b*c*", No::CaseInsensitive));

    EXPECT_TRUE(No::wildCmp("I_am!~bar@foo", "*!?bar@foo", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("I_am!~bar@foo", "*!?bar@foo", No::CaseInsensitive));

    EXPECT_FALSE(No::wildCmp("I_am!~bar@foo", "*!?BAR@foo", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("I_am!~bar@foo", "*!?BAR@foo", No::CaseInsensitive));

    EXPECT_TRUE(No::wildCmp("abc", "*a*b*c*", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("abc", "*a*b*c*", No::CaseInsensitive));

    EXPECT_FALSE(No::wildCmp("abc", "*A*b*c*", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("abc", "*A*b*c*", No::CaseInsensitive));

    EXPECT_FALSE(No::wildCmp("Abc", "*a*b*c*", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("Abc", "*a*b*c*", No::CaseInsensitive));

    EXPECT_TRUE(No::wildCmp("axbyc", "*a*b*c*", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("axbyc", "*a*b*c*", No::CaseInsensitive));

    EXPECT_FALSE(No::wildCmp("AxByC", "*a*B*c*", No::CaseSensitive));
    EXPECT_TRUE(No::wildCmp("AxByC", "*a*B*c*", No::CaseInsensitive));
}

TEST(UtilsTest, Token)
{
    EXPECT_EQ("a", No::token("a b c", 0));
    EXPECT_EQ("b", No::token("a b c", 1));
    EXPECT_EQ("", No::token("a b c", 100));
    EXPECT_EQ("b c", No::tokens("a b c", 1));
    EXPECT_EQ("c", No::token("a  c", 1));
    EXPECT_EQ("c", No::token("a  c", 1, " "));
    EXPECT_EQ("c", No::token("a  c", 1, "  "));
    EXPECT_EQ(" c", No::token("a   c", 1, "  "));
    EXPECT_EQ("c", No::token("a    c", 1, "  "));
//    EXPECT_EQ("(b c)", No::token("a (b c) d", 1, " ", "(", ")"));
//    EXPECT_EQ("d", No::token("a (b c) d", 2, " ", "(", ")"));
}
