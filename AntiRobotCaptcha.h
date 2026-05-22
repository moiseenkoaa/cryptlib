
#define ANTIROBOT_IPV6_SUPPORT

#ifdef ANTIROBOT_IPV6_SUPPORT
#define ANTIROBOT_IP _IP6
#else
#define ANTIROBOT_IP _IP
#endif

class CAntiRobot
{
    CMaaFile m_f;
    struct sNumRec
    {
        ANTIROBOT_IP m_Ip;
        char m_Hash[8];
        _dword m_Op;
        _dword m_Arg1, m_Arg2;
        _dword m_Time;
        _dword m_Tries;
    };
    int m_MaxTriesNumber;
    int m_MaxRecords;
    CMaaPtr_<sNumRec, -1> m_Recs;
    int m_IsModified;
    int m_MaxCaptcheRequests;
    int m_RequestsPeriod;
    int m_MaxCaptcheValidStore;
    int m_MaxCaptcheSuccessfulAccepts;
    int m_MaxCaptcheSuccessfulAcceptsPeriod;
public:
    CAntiRobot(CMaaString fn, bool bThrow = false, int MaxCaptcheRequests = 20, int RequestsPeriod = 15 * 60, int MaxTriesNumber = 20, int MaxCaptcheValidStore = 60 * 60, int MaxRecords = 1000, int MaxCaptcheSuccessfulAccepts = 10/2*7, int MaxCaptcheSuccessfulAcceptsPeriod = 24 * 3600);
    ~CAntiRobot();
    int Set(ANTIROBOT_IP Ip, CMaaString &OutHash /*8 bytes text*/, CMaaString &Question, int QuestionType = '+');
    //    int GetAnswer(ANTIROBOT_IP Ip, CMaaString Hash); // -1 on error
    bool Check(ANTIROBOT_IP Ip, int Num, CMaaString Hash, CMaaString *pexterr = nullptr) noexcept;
    bool Check(ANTIROBOT_IP Ip, CMaaString Reply, CMaaString Hash, CMaaString *pexterr = nullptr) noexcept;
    int GenerateHash(ANTIROBOT_IP Ip, CMaaString &OutHash, CMaaString *pQuestion = nullptr, int QuestionType = '+');
    int GetQuestion(ANTIROBOT_IP Ip, CMaaString Hash, CMaaString &Question) noexcept;
private:
protected:
    _dword m_Temp;
    _dword MaskInt(_dword x, _dword Mask) noexcept;
};
