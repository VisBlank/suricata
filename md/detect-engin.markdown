begin: DetectEngineRegisterAppInspectionEngines

    SigParseProto <-
    SigParseBasics <-
    SigParse <-         ->  SigParseOptions
    SigInitHelper <-
    SigInit <-
    DetectEngineAppendSig <-
    DetectLoadSigFile <-
    SigLoadSignaturesa <-
    LoadSignatures <-
    main

    DetectAppLayerEventSetup <-
    DetectAppLayerEventParse <-
    DetectAppLayerEventParseApp|DetectAppLayerEventParsePkt <-
    AppLayerGetEventInfo <-
    al_proto_table[alproto].StateGetEventInfo <-
