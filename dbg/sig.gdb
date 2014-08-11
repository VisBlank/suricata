
#-------------------- signature --------------------------
#b LoadSignatures
#b SigLoadSignatures
#b DetectLoadSigFile
#b SigParse 
#b DetectAppLayerEventSetup
#b DetectHttpUriRegister
#b SigTableSetup
#
#b DetectCsumRegister
#b DetectTCPV4CsumMatch
#b DetectTCPV4CsumSetup
#
#b DetectIPV4CsumMatch
#b DetectIPV4CsumSetup
#b DetectMysqlKeywordsRegister
#b DetectMysqlUserALMatch
#b DetectMysqlUserSetup
#b DetectMysqlUserNameFree
#b SigMatchSignatures
#b DeStateDetectStartDetection
#b DeStateDetectContinueDetection
#b detect-engin-state.c:378
#b detect-engin-state.c:623
#b detect.c:1485
#    commands
#    silent
#    print *sm
#    p sigmatch_table[sm->type]
#    cont
#    end
#b detect.c:615
#    commands
#    silent
#    print *sm
#    p sigmatch_table[sm->type]
#    cont
#    end
#b detect-engine-iponly.c:929
#    commands
#    silent
#    print *sm
#    p sigmatch_table[sm->type]
#    cont
#    end
#b detect-engine-iponly.c:1073
#    commands
#    silent
#    print *sm
#    p sigmatch_table[sm->type]
#    cont
#    end

#b SigParse 
#b LoadSignatures 
#b SigInitHelper
#b SigInit
#b DetectEngineAppendSig
#b DetectLoadSigFile
#b SigLoadSignaturesa
#b SigParseOptions
#b detect-parse.c:547
#    commands
#    silent
#    print optvalue
#    cont
#    end
#
#b detect-parse.c:521
#    commands
#    silent
#    print optname
#    if optname == "tcpv4-csum"
#        print "got it!" 
#    else
#        cont
#    end
#    end
