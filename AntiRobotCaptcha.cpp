//==============================================================================
// PROJECT: ToolsLib
//==============================================================================
// FILE:       AntiRobotCaptcha.cpp
//
// AUTHOR:     Andrey A. Moiseenko
//
//==============================================================================
#include "stdafx.h"
#include "temp.h"

//#include "perm.h"
//#include "temp.h"

#define MAX_TRY_N 20 // number of guess and number of reg tryes for last 15 minutes
#define MAX_TRY_PATTERN 0x11111111

CAntiRobot::CAntiRobot(CMaaString fn, bool bThrow, int MaxCaptcheRequests, int RequestsPeriod, int MaxTriesNumber, int MaxCaptcheValidStore, int MaxRecords, int MaxCaptcheSuccessfulAccepts, int MaxCaptcheSuccessfulAcceptsPeriod)
:   m_f(fn, CMaaFile::eRWCD_SrSw, bThrow),
    m_MaxTriesNumber(MaxTriesNumber <= -100 ? MAX_TRY_N : MaxTriesNumber),
    m_Recs(m_MaxRecords = (MaxRecords >= 100 ? MaxRecords : 100)/*, bThrow ? 1 : 0*/),
    m_IsModified(0),
    m_MaxCaptcheRequests(MaxCaptcheRequests),
    m_RequestsPeriod(RequestsPeriod),
    m_MaxCaptcheValidStore(MaxCaptcheValidStore),
    m_MaxCaptcheSuccessfulAccepts(MaxCaptcheSuccessfulAccepts),
    m_MaxCaptcheSuccessfulAcceptsPeriod(MaxCaptcheSuccessfulAcceptsPeriod)
{
    m_MaxTriesNumber = m_MaxTriesNumber < MAX_TRY_PATTERN ? m_MaxTriesNumber : MAX_TRY_PATTERN;
    if  (m_Recs.IsValid())
    {
        m_Recs.Zero();
    }
    else
    {
        if (bThrow)
        {
            CMaaPtr_THROW1;
        }
        m_MaxRecords = 0;
    }
    if  (m_f.IsOpen())
    {
        m_f.Read(m_Recs, (_dword)m_Recs.Size());
        m_f.Seek(0);
    }
}

CAntiRobot::~CAntiRobot()
{
    if  (m_f.IsOpen() && m_IsModified)
    {
        try
        {
            m_f.Seek(0);
            m_f.Write(m_Recs, (_dword)m_Recs.Size());
        }
        catch (...)
        {
        }
        m_f.Close();
    }
}

int CAntiRobot::Set(ANTIROBOT_IP Ip, CMaaString &OutHash /*8+1 bytes*/, CMaaString &Question, int QuestionType)
{
    OutHash = CMaaStringRO("unknown_hash_error");
    _dword x = 0;
    if  (m_f.IsOpen())
    {
        CMaaString Ops = CMaaStringRO("+-*/");
        if  ((QuestionType & 0xff) != QuestionType || Ops.Find((char)QuestionType) < 0)
        {
            GetRnd(&QuestionType, (int)sizeof(QuestionType));
            QuestionType = Ops[(int)((unsigned)QuestionType % 4)];
        }

        int rnd1 = 0, rnd2 = 0;

        GetRnd(&rnd1, sizeof(rnd1));
        GetRnd(&rnd2, sizeof(rnd2));

        switch(QuestionType)
        {
        case '+':
        case '-':
            rnd1 = 10 + (unsigned)rnd1 % 90U;
            rnd2 = 10 + (unsigned)rnd2 % 90U;
            break;
        case '*':
            rnd1 = 1 + (unsigned)rnd1 % 9U;
            rnd2 = 10 + (unsigned)rnd2 % 90U;
            break;
        case '/':
            rnd2 = 1 + (unsigned)rnd2 % 9U;
            rnd1 = (10 + (unsigned)rnd1 % 90U) / rnd2;
            rnd1 *= rnd2;
            break;
        }

        CMaaString Text = CMaaStringRO("This is a text");
        Text.Format("%d %c %d = ", rnd1, (char)QuestionType, rnd2);

        GetRnd(&x, (int)sizeof(x));

        const _dword t = (_dword)time(nullptr);
        _dword t0 = 0;
        int i;
        int n = 0;
        int j = 0;
        int nAcceptsCompleted = 0;
        for (i = 0; i < m_MaxRecords; i++)
        {
            if  ((_sdword)(m_Recs[i].m_Time - t) > m_MaxCaptcheSuccessfulAcceptsPeriod || (_sdword)(m_Recs[i].m_Time - t) < -m_MaxCaptcheSuccessfulAcceptsPeriod)
            {
                m_Recs[i].m_Time = 0;
            }
            if  (m_Recs[i].m_Ip == Ip && (_sdword)(m_Recs[i].m_Time - t) > -m_RequestsPeriod && (_sdword)(m_Recs[i].m_Time - t) < m_RequestsPeriod)
            {
                n++;
                t0 = (_sdword)(t0 - m_Recs[i].m_Time) > 0 || t0 == 0 ? m_Recs[i].m_Time : t0;
            }
            if  (m_Recs[i].m_Ip == Ip && m_Recs[i].m_Tries == MAX_TRY_PATTERN && (_sdword)(m_Recs[i].m_Time - t) > -m_MaxCaptcheSuccessfulAcceptsPeriod && (_sdword)(m_Recs[i].m_Time - t) < m_MaxCaptcheSuccessfulAcceptsPeriod)
            {
                nAcceptsCompleted++;
            }
            if  ((_sdword)(m_Recs[i].m_Time - m_Recs[j].m_Time) < 0 || !m_Recs[i].m_Time)
            {
                j = i;
            }
        }
        if  (nAcceptsCompleted >= m_MaxCaptcheSuccessfulAccepts)
        {
            Text.Format("Maximum (%d) accepts was received from your IP address within %d day(s), contact site administrator to resolve this problem if it is need to be solved (for cellular, wireless or home networks, for example)", nAcceptsCompleted, (m_MaxCaptcheSuccessfulAcceptsPeriod + 24 * 3600 - 1) / (24 * 3600));
            Question = Text;
        }
        else if (n < m_MaxCaptcheRequests)
        {
            m_IsModified = 1;
            Question = Text;
            OutHash.Format("%08X", x);
            memcpy(m_Recs[j].m_Hash, OutHash, 8);
            m_Recs[j].m_Ip = Ip;
            m_Recs[j].m_Op = QuestionType;
            m_Recs[j].m_Arg1 = rnd1;
            m_Recs[j].m_Arg2 = rnd2;
            m_Recs[j].m_Time = t;
            m_Recs[j].m_Tries = 0;
            return 1;
        }
        else if (n >= m_MaxCaptcheRequests && t0)
        {
            const int s = (int)(m_RequestsPeriod - (int)(t - t0));
            if  (s > 0)
            {
                Text.Format("try %d minutes later", (s + 59) / 60);
                Question = Text;
            }
        }
        return -1;
    }
    return 0;
}

int CAntiRobot::GenerateHash(ANTIROBOT_IP Ip, CMaaString &OutHash, CMaaString *pQuestion, int QuestionType)
{
    CMaaString Question;
    return Set(Ip, OutHash, pQuestion ? *pQuestion : Question, QuestionType);
}

int CAntiRobot::GetQuestion(ANTIROBOT_IP Ip, CMaaString Hash, CMaaString &Question) noexcept
{
    const _dword t = (_dword)time(nullptr);
    _dword t0 = 0;
    int n = 0;
    int nAcceptsCompleted = 0;
    for (int i = 0; i < m_MaxRecords; i++)
    {
        if  (m_Recs[i].m_Ip == Ip && (_sdword)(m_Recs[i].m_Time - t) > -m_RequestsPeriod && (_sdword)(m_Recs[i].m_Time - t) < m_RequestsPeriod)
        {
            n++;
            t0 = (_sdword)(t0 - m_Recs[i].m_Time) > 0 || t0 == 0 ? m_Recs[i].m_Time : t0;
        }
        if  (m_Recs[i].m_Ip == Ip && m_Recs[i].m_Tries == MAX_TRY_PATTERN && (_sdword)(m_Recs[i].m_Time - t) > -m_MaxCaptcheSuccessfulAcceptsPeriod && (_sdword)(m_Recs[i].m_Time - t) < m_MaxCaptcheSuccessfulAcceptsPeriod)
        {
            nAcceptsCompleted++;
        }
        if  (m_Recs[i].m_Ip == Ip && Hash == CMaaString(m_Recs[i].m_Hash, 8, CMaaString::eMemString))
        {
            if  ((_sdword)(m_Recs[i].m_Time - t) > -m_MaxCaptcheValidStore && (_sdword)(m_Recs[i].m_Time - t) < m_MaxCaptcheValidStore && m_Recs[i].m_Tries < (_dword)m_MaxTriesNumber)
            {
                CMaaString Ops = CMaaStringRO("+-*/");
                const int QuestionType = m_Recs[i].m_Op;
                if  ((QuestionType & 0xff) == QuestionType && Ops.Find((char)QuestionType) >= 0)
                {
                    CMaaString Text = CMaaStringRO("This is a text");
                    Text.Format2("%d%c%d", "%1 %2 %3 = ", m_Recs[i].m_Arg1, (char)QuestionType, m_Recs[i].m_Arg2);
                    Question = Text;
                    return 1;
                }
            }
            else
            {
                CMaaString Text;
                if  (m_Recs[i].m_Tries < (_dword)m_MaxTriesNumber)
                {
                    Text.Format2("%d%d%d", "Time expired (%2 min of %3), reload the captcha", (int)(t - m_Recs[i].m_Time), (int)(t - m_Recs[i].m_Time) / 60, 60);
                }
                else if (m_Recs[i].m_Tries == MAX_TRY_PATTERN)
                {
                    Text.Format2("", "Already answered and accepted, renew the captcha");
                }
                else// if (m_Recs[i].m_Tries == MAX_TRY_PATTERN)
                {
                    Text.Format2("%d%d", "Tries limit exceeded (%1 of %2), reload the captcha", (int)m_Recs[i].m_Tries, (int)m_MaxTriesNumber);
                }
                Question = Text;
                return -1;
            }
        }
    }
    /*
    if (n < m_MaxCaptcheRequests)
    {
	m_IsModified = 1;
	Question = Text;
	return 1;
    }
    */
    if  (nAcceptsCompleted >= m_MaxCaptcheSuccessfulAccepts)
    {
        CMaaString Text;
        Text.Format("Maximum (%d) accepts was received from your IP address within %d day(s), contact site administrator to resolve this problem if it is need to be solved (for cellular, wireless or home networks, for example)", nAcceptsCompleted, (m_MaxCaptcheSuccessfulAcceptsPeriod + 24 * 3600 - 1) / (24 * 3600));
        Question = Text;
        return -1;
    }
    if  (n >= m_MaxCaptcheRequests && t0)
    {
        const int s = (int)(m_RequestsPeriod - (int)(t - t0));
        if  (s > 0)
        {
            CMaaString Text;
            Text.Format("%d requests was processed within %d minutes, try %d minutes later", n, (int)m_RequestsPeriod / 60, (s + 59) / 60);
            Question = Text;
            return -1;
        }
    }
    return 0;
}

/*
int CAntiRobot::GetAnswer(ANTIROBOT_IP Ip, CMaaString Hash) // -1 on error
{
    long t = (long)time(nullptr);
    for (int i = 0; i < m_MaxRecords; i++)
    {
	if (m_Recs[i].m_Ip == Ip && 
	    Hash == CMaaString(m_Recs[i].m_Hash, 8) &&
	     m_Recs[i].m_Time > t - m_MaxCaptcheValidStore &&
	     m_Recs[i].m_Time < t + m_MaxCaptcheValidStore &&
	     m_Recs[i].m_Tries < (_dword)m_MaxTriesNumber
	     )
	{
	    m_IsModified = 1;
    	    m_Recs[i].m_Tries++;
	    return m_Recs[i].m_Arg1 + m_Recs[i].m_Arg2;
	}
    }
    return -1;
}
*/

_dword g_Temp_dword______________________________________ = 1234567890;
_dword CAntiRobot::MaskInt(_dword x, _dword Mask) noexcept
{
    const _dword r = x & Mask;
    m_Temp = r + 12345678;
    g_Temp_dword______________________________________ += m_Temp + 987654321;
    return r;
}

bool CAntiRobot::Check(ANTIROBOT_IP Ip, int Num, CMaaString Hash, CMaaString *pexterr) noexcept
{
    if  (Num < 1)
    {
        pexterr && pexterr->Format("Num = %d (< 1)", Num);
        return false;
    }
    const _dword t = (_dword)time(nullptr);
    for (int i = 0; i < m_MaxRecords; i++)
    {
        if  (m_Recs[i].m_Ip == Ip)
        {
            CMaaString temp(m_Recs[i].m_Hash, 8, CMaaString::eMemString);
            pexterr && pexterr->Format("%S\ni=%d, Hash[i]=%S, m_Recs[i].m_Hash=%S, t-m_Recs[i].m_Time=%d, m_Recs[i].m_Tries=%d", pexterr, i, &Hash, &temp, (int)(t-m_Recs[i].m_Time), m_Recs[i].m_Tries);
        }
        if  (m_Recs[i].m_Ip == Ip && (Hash.IsEmpty() || Hash == CMaaString(m_Recs[i].m_Hash, 8, CMaaString::eMemString)) && (_sdword)(m_Recs[i].m_Time - t) > -m_MaxCaptcheValidStore && (_sdword)(m_Recs[i].m_Time - t) < m_MaxCaptcheValidStore && m_Recs[i].m_Tries < (_dword)m_MaxTriesNumber)
        {
            if  (m_Recs[i].m_Tries < MAX_TRY_PATTERN)
            {
                m_IsModified = 1;
                int Answer = -1;
                if  (m_Recs[i].m_Tries++ < (_dword)m_MaxTriesNumber)
                {
                    if  (m_Recs[i].m_Op == '+' || m_Recs[i].m_Op == '-')
                    {
                        _dword Mask = 0;
                        while(1)
                        {
                            const _dword NewMask = (Mask << 1) | 1;
                            if  (NewMask == Mask)
                            {
                                Answer = m_Recs[i].m_Op == '+' ?
                                m_Recs[i].m_Arg1 + m_Recs[i].m_Arg2 :
                                m_Recs[i].m_Arg1 - m_Recs[i].m_Arg2;
                                break;
                            }
                            Mask = NewMask;
                            const int x1 = MaskInt(m_Recs[i].m_Arg1, Mask);
                            const int x2 = MaskInt(m_Recs[i].m_Arg2, Mask);
                            const int x = MaskInt(m_Recs[i].m_Op == '+' ? x1 + x2 : x1 - x2, Mask);
                            const int n = MaskInt(Num, Mask);
                            if  (n != x)
                            {
                                break;
                            }
                        }
                    }
                    switch(m_Recs[i].m_Op)
                    {
                    case '+':
                        //Answer = m_Recs[i].m_Arg1 + m_Recs[i].m_Arg2;
                        break;
                    case '-':
                        //Answer = m_Recs[i].m_Arg1 - m_Recs[i].m_Arg2;
                        break;
                    case '*':
                        Answer = m_Recs[i].m_Arg1 * m_Recs[i].m_Arg2;
                        break;
                    case '/':
                        Answer = m_Recs[i].m_Arg2 != 0 ? m_Recs[i].m_Arg1 / m_Recs[i].m_Arg2 : Answer;
                        break;
                    }
                    if  (Num == Answer && Answer != -1)
                    {
                        m_Recs[i].m_Tries = MAX_TRY_PATTERN;
                        return true;
                    }
                    else
                    {
                        pexterr && pexterr->Format("Num=%d != ... arg1=%d, arg2=%d, op=%c", Num, m_Recs[i].m_Arg1, m_Recs[i].m_Arg2, (char)m_Recs[i].m_Op);
                    }
                }
                else
                {
                    pexterr && pexterr->Format("m_Recs[i].m_Tries >= MAX_TRY_PATTERN (%d >= %d)", m_Recs[i].m_Tries, MAX_TRY_PATTERN);
                }
            }
        }
    }
    return false;
}

bool CAntiRobot::Check(ANTIROBOT_IP Ip, CMaaString Reply, CMaaString Hash, CMaaString *pexterr) noexcept
{
    //int Num = -1;
    //CMaaString r = Reply.NewCopy();
    //CMaaString h = Hash.NewCopy();
    //sscanf(r, "%d", &Num);
    //return Check(Ip, Num, h, pexterr);
    return Check(Ip, Reply.ToInt(-1), Hash, pexterr);
    //int Num = -1;
    //sscanf(Reply, "%d", &Num);
    //return Check(Ip, Num, Hash, pexterr);
}
