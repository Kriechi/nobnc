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
#include <no/nofile.h>
#include <no/noutils.h>

TEST(IRC32, GetMessageTags)
{
    EXPECT_EQ(NoStringMap(), NoUtils::GetMessageTags(""));
    EXPECT_EQ(NoStringMap(), NoUtils::GetMessageTags(":nick!ident@host PRIVMSG #chan :hello world"));

    NoStringMap exp;
    exp["a"] = "b";
    EXPECT_EQ(exp, NoUtils::GetMessageTags("@a=b"));
    EXPECT_EQ(exp, NoUtils::GetMessageTags("@a=b :nick!ident@host PRIVMSG #chan :hello world"));
    EXPECT_EQ(exp, NoUtils::GetMessageTags("@a=b :rest"));
    exp.clear();

    exp["ab"] = "cdef";
    exp["znc.in/gh-ij"] = "klmn,op";
    EXPECT_EQ(exp, NoUtils::GetMessageTags("@ab=cdef;znc.in/gh-ij=klmn,op :rest"));
    exp.clear();

    exp["a"] = "==b==";
    EXPECT_EQ(exp, NoUtils::GetMessageTags("@a===b== :rest"));
    exp.clear();

    exp["a"] = "";
    exp["b"] = "c";
    exp["d"] = "";
    EXPECT_EQ(exp, NoUtils::GetMessageTags("@a;b=c;d :rest"));
    exp.clear();

    exp["semi-colon"] += ';';
    exp["space"] += ' ';
    exp["NUL"] += '\0';
    exp["backslash"] += '\\';
    exp["CR"] += '\r';
    exp["LF"] += '\n';
    EXPECT_EQ(exp, NoUtils::GetMessageTags(R"(@semi-colon=\:;space=\s;NUL=\0;backslash=\\;CR=\r;LF=\n :rest)"));
    exp.clear();

    exp["a"] = "; \\\r\n";
    EXPECT_EQ(exp, NoUtils::GetMessageTags(R"(@a=\:\s\\\r\n :rest)"));
    exp.clear();
}

TEST(IRC32, SetMessageTags)
{
    NoString sLine;

    sLine = ":rest";
    NoUtils::SetMessageTags(sLine, NoStringMap());
    EXPECT_EQ(":rest", sLine);

    NoStringMap tags;
    tags["a"] = "b";
    NoUtils::SetMessageTags(sLine, tags);
    EXPECT_EQ("@a=b :rest", sLine);

    tags["c"] = "d";
    NoUtils::SetMessageTags(sLine, tags);
    EXPECT_EQ("@a=b;c=d :rest", sLine);

    tags["e"] = "";
    NoUtils::SetMessageTags(sLine, tags);
    EXPECT_EQ("@a=b;c=d;e :rest", sLine);
    tags.clear();

    tags["semi-colon"] += ';';
    tags["space"] += ' ';
    tags["NUL"] += '\0';
    tags["backslash"] += '\\';
    tags["CR"] += '\r';
    tags["LF"] += '\n';
    NoUtils::SetMessageTags(sLine, tags);
    EXPECT_EQ(R"(@CR=\r;LF=\n;NUL=\0;backslash=\\;semi-colon=\:;space=\s :rest)", sLine);
    tags.clear();

    tags["a"] = "; \\\r\n";
    NoUtils::SetMessageTags(sLine, tags);
    EXPECT_EQ(R"(@a=\:\s\\\r\n :rest)", sLine);
}
