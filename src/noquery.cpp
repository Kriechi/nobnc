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

#include "noquery.h"
#include "nouser.h"
#include "nonetwork.h"

NoQuery::NoQuery(const NoString& sName, NoNetwork* pNetwork) : m_sName(sName), m_pNetwork(pNetwork), m_Buffer()
{
    SetBufferCount(m_pNetwork->GetUser()->GetBufferCount(), true);
}

NoQuery::~NoQuery() {}

void NoQuery::SendBuffer(NoClient* pClient) { SendBuffer(pClient, m_Buffer); }

void NoQuery::SendBuffer(NoClient* pClient, const NoBuffer& Buffer)
{
    if (m_pNetwork && m_pNetwork->IsUserAttached()) {
        // Based on NoChannel::SendBuffer()
        if (!Buffer.isEmpty()) {
            const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();
            for (NoClient* pEachClient : vClients) {
                NoClient* pUseClient = (pClient ? pClient : pEachClient);

                NoStringMap msParams;
                msParams["target"] = pUseClient->GetNick();

                bool bWasPlaybackActive = pUseClient->IsPlaybackActive();
                pUseClient->SetPlaybackActive(true);

                bool bBatch = pUseClient->HasBatch();
                NoString sBatchName = m_sName.MD5();

                if (bBatch) {
                    m_pNetwork->PutUser(":znc.in BATCH +" + sBatchName + " znc.in/playback " + m_sName, pUseClient);
                }

                size_t uSize = Buffer.size();
                for (size_t uIdx = 0; uIdx < uSize; uIdx++) {
                    const NoMessage& BufLine = Buffer.getMessage(uIdx);

                    if (!pUseClient->HasSelfMessage()) {
                        NoNick Sender(BufLine.GetFormat().Token(0));
                        if (Sender.NickEquals(pUseClient->GetNick())) {
                            continue;
                        }
                    }

                    NoString sLine = BufLine.GetLine(*pUseClient, msParams);
                    if (bBatch) {
                        NoStringMap msBatchTags = NoUtils::GetMessageTags(sLine);
                        msBatchTags["batch"] = sBatchName;
                        NoUtils::SetMessageTags(sLine, msBatchTags);
                    }
                    bool bContinue = false;
                    NETWORKMODULECALL(OnPrivBufferPlayLine2(*pUseClient, sLine, BufLine.GetTime()),
                                      m_pNetwork->GetUser(),
                                      m_pNetwork,
                                      nullptr,
                                      &bContinue);
                    if (bContinue) continue;
                    m_pNetwork->PutUser(sLine, pUseClient);
                }

                if (bBatch) {
                    m_pNetwork->PutUser(":znc.in BATCH -" + sBatchName, pUseClient);
                }

                pUseClient->SetPlaybackActive(bWasPlaybackActive);

                if (pClient) break;
            }
        }
    }
}
