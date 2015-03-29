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
#include <no/nonetwork.h>
#include <no/nouser.h>
#include <no/noapp.h>

class NetworkTest : public ::testing::Test
{
protected:
    void SetUp()
    {
        NoApp::CreateInstance();
    }
    void TearDown()
    {
        NoApp::DestroyInstance();
    }
};

TEST_F(NetworkTest, FindChan)
{
    NoUser user("user");
    NoNetwork network(&user, "network");

    EXPECT_TRUE(network.addChannel("#foo", false));
    EXPECT_TRUE(network.addChannel("#Bar", false));
    EXPECT_TRUE(network.addChannel("#BAZ", false));

    EXPECT_TRUE(network.findChannel("#foo"));
    EXPECT_TRUE(network.findChannel("#Bar"));
    EXPECT_TRUE(network.findChannel("#BAZ"));

    EXPECT_TRUE(network.findChannel("#Foo"));
    EXPECT_TRUE(network.findChannel("#BAR"));
    EXPECT_TRUE(network.findChannel("#baz"));

    EXPECT_FALSE(network.findChannel("#f"));
    EXPECT_FALSE(network.findChannel("&foo"));
    EXPECT_FALSE(network.findChannel("##foo"));
}

TEST_F(NetworkTest, findChannels)
{
    NoUser user("user");
    NoNetwork network(&user, "network");

    EXPECT_TRUE(network.addChannel("#foo", false));
    EXPECT_TRUE(network.addChannel("#Bar", false));
    EXPECT_TRUE(network.addChannel("#BAZ", false));

    EXPECT_EQ(network.findChannels("#f*").size(), 1);
    EXPECT_EQ(network.findChannels("#b*").size(), 2);
    EXPECT_EQ(network.findChannels("#?A*").size(), 2);
    EXPECT_EQ(network.findChannels("*z").size(), 1);
}

TEST_F(NetworkTest, findQuery)
{
    NoUser user("user");
    NoNetwork network(&user, "network");

    EXPECT_TRUE(network.addQuery("foo"));
    EXPECT_TRUE(network.addQuery("Bar"));
    EXPECT_TRUE(network.addQuery("BAZ"));

    EXPECT_TRUE(network.findQuery("foo"));
    EXPECT_TRUE(network.findQuery("Bar"));
    EXPECT_TRUE(network.findQuery("BAZ"));

    EXPECT_TRUE(network.findQuery("Foo"));
    EXPECT_TRUE(network.findQuery("BAR"));
    EXPECT_TRUE(network.findQuery("baz"));

    EXPECT_FALSE(network.findQuery("f"));
    EXPECT_FALSE(network.findQuery("fo"));
    EXPECT_FALSE(network.findQuery("FF"));
}

TEST_F(NetworkTest, findQueries)
{
    NoUser user("user");
    NoNetwork network(&user, "network");

    EXPECT_TRUE(network.addQuery("foo"));
    EXPECT_TRUE(network.addQuery("Bar"));
    EXPECT_TRUE(network.addQuery("BAZ"));

    EXPECT_EQ(network.findQueries("f*").size(), 1);
    EXPECT_EQ(network.findQueries("b*").size(), 2);
    EXPECT_EQ(network.findQueries("?A*").size(), 2);
    EXPECT_EQ(network.findQueries("*z").size(), 1);
}
