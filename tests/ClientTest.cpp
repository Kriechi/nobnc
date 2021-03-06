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
#include <nobnc/noclient.h>
#include <nobnc/noapp.h>

class ClientTest : public ::testing::Test
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
    void testPass(const NoString& sInput, const NoString& sUser, const NoString& identifier, const NoString& sNetwork, const NoString& pass) const
    {
        NoClient client;
        client.ParsePass(sInput);
        EXPECT_EQ(sUser, client.m_sUser);
        EXPECT_EQ(identifier, client.m_sIdentifier);
        EXPECT_EQ(sNetwork, client.m_sNetwork);
        EXPECT_EQ(pass, client.m_sPass);
    }

    void testUser(const NoString& sInput, const NoString& sUser, const NoString& identifier, const NoString& sNetwork) const
    {
        NoClient client;
        client.ParseUser(sInput);
        EXPECT_EQ(sUser, client.m_sUser);
        EXPECT_EQ(identifier, client.m_sIdentifier);
        EXPECT_EQ(sNetwork, client.m_sNetwork);
    }
};

TEST_F(ClientTest, Pass)
{
    testPass("p@ss#w0rd", "", "", "", "p@ss#w0rd");
    testPass("user:p@ss#w0rd", "user", "", "", "p@ss#w0rd");
    testPass("user/net-work:p@ss#w0rd", "user", "", "net-work", "p@ss#w0rd");
    testPass("user@identifier:p@ss#w0rd", "user", "identifier", "", "p@ss#w0rd");
    testPass("user@identifier/net-work:p@ss#w0rd", "user", "identifier", "net-work", "p@ss#w0rd");

    testPass("user@bnc.no:p@ss#w0rd", "user@bnc.no", "", "", "p@ss#w0rd");
    testPass("user@bnc.no/net-work:p@ss#w0rd", "user@bnc.no", "", "net-work", "p@ss#w0rd");
    testPass("user@bnc.no@identifier:p@ss#w0rd", "user@bnc.no", "identifier", "", "p@ss#w0rd");
    testPass("user@bnc.no@identifier/net-work:p@ss#w0rd", "user@bnc.no", "identifier", "net-work", "p@ss#w0rd");
}

TEST_F(ClientTest, User)
{
    testUser("user/net-work", "user", "", "net-work");
    testUser("user@identifier", "user", "identifier", "");
    testUser("user@identifier/net-work", "user", "identifier", "net-work");

    testUser("user@bnc.no/net-work", "user@bnc.no", "", "net-work");
    testUser("user@bnc.no@identifier", "user@bnc.no", "identifier", "");
    testUser("user@bnc.no@identifier/net-work", "user@bnc.no", "identifier", "net-work");
}
