# suricata 基础知识

## 主要概念

* packet pipeline
* run mode
* capture device: pcap, pcap file, nfqueue, ipfw

    -i pcap-device
    -r pcap-files
    -q nfqueue

## module
module 用来封装一组回调函数（`init`, `deinit`），packet 管道中的每个线程就是一个 module 实例， 线程通过定义于 `runmode.c` 中的 runmode 来初始化。runmode 同时还初始化 queue 以及packet handlers，这些 handler 用来在 module 和 queue 中传递 packet。当 runmode 中所有这些初始化步骤都完成后，线程就被标记为 runable。

management 线程用于在 packet 管道之外来处理任务。

## pcap 
### capture module
通过传递设备名称来初始化 pcap device，比如 「eth0」，一旦设备初始化后，便会收集数据传送给 suricata，之后 suricata 作为一个这些数据的「薄封装层」，使得这些数据能兼容于 decoder 中的链接类型。

### decode module
decoding 的过程就是将一组数据转化成 suricata 所支持的数据结构。这些数据被递交给特定类型链接 decoder，当前支持的链接类型有 `LINKTYPE_LINUX_SSL`, `LINKTYPE_ETHERNET`, `LINKTYPE_PPP`, `LINKTYPE_RAW`

### stream module

### detect module
detect module 用来处理很多任务：载入所有 signature，初始化 detect plugin，为 packet 路由创建 detect group，最后再将这些 packet 过一遍 rules。

## IDS/IPS mode

# 新增 capture mode

* 编写实现 capture 的代码: (src/source-xxx-packet.{ch})
* 选择专用的 run mode    : (src/runmode-xxx-packet.{ch})

## 将新增代码添加到编译规则中
在 `src/Makefile.am` 中：

    suricata_SOURCES = 
     ...
     runmode-xxx-packet.c  runmode-xxx-packet.h \
     source-xxx-packet.c  source-xxx-packet.h \\
     ...

在 `configure.ac` 中，增加选项配置

 # XXX_PACKET support
     AC_ARG_ENABLE(xxx-packet,
                AS_HELP_STRING([--enable-xxx-packet], [Enable XXX_PACKET support [default=yes]]),
                ,[enable_xxx_packet=yes])

将 xxx-packet 的 capture 代码添加到下面的宏内部：

    #ifdef HAVE_XXX_PACKET
    ...
    #endif

增加 `AS_IP` 项:

    AS_IF([test "x$enable_xxx_packet" = "xyes"], [
            AC_CHECK_DECL([TPACKET_V2],
                AC_DEFINE([HAVE_XXX_PACKET],[1],[XXX_PACKET support is available]),
                [enable_af_packet="no"],
                )])

最后在 `configure.ac` 中新增如下内容，以表示该 capture module 是否编译:

    echo "
    suricata configuration:
    XXX_PACKET: ${enable_xxx_packet}

## 声明 capture mode
我们需要告知 suricata 来了一个新的 capture mode，通过填充 `tmm_modules` 数组即可达到该目的。首先要做的就是声明新的 module，在 `src/tm-threads-common.h` 中更新一下 `TmmID` 的枚举：

* `TMM_RECEIVE_XXX_PACKET`
* `TMM_DECODE_XXX_PACKET`

在 `src/source-xxx-packet.c` 中新增

    void TmModuleRecivexxxPacketRegister(void) {
        tmm_modules[TMM_RECEIVE_XXX_PACKET].name = "ReceivexxxPacket";
        /* capture 线程启动时调用该函数 */
        tmm_modules[TMM_RECEIVE_XXX_PACKET].ThreadInit = ReceivexxxPacketThreadInit;

        tmm_modules[TMM_RECEIVE_XXX_PACKET].Func = NULL;

        /* `I do the work!`， 从 capture 系统中读取数据，创建 packet 并将它们发送到处理系统 */
        tmm_modules[TMM_RECEIVE_XXX_PACKET].PktAcqLoop = ReceivexxxPacketLoop;
        tmm_modules[TMM_RECEIVE_XXX_PACKET].ThreadExitPrintStats = ReceivexxxPacketThreadExitStats;

        /* capture 线程结束时调用 */
        tmm_modules[TMM_RECEIVE_XXX_PACKET].ThreadDeinit = NULL;

        /* 定义单元测试 */
        tmm_modules[TMM_RECEIVE_XXX_PACKET].RegisterTests = NULL;

        /* define the capabilities need for the capture thread */
        tmm_modules[TMM_RECEIVE_XXX_PACKET].cap_flags = SC_CAP_NET_RAW;

        /* always define to TM_FLAG_RECEIVE_TM for a receive module */
        tmm_modules[TMM_RECEIVE_XXX_PACKET].flags = TM_FLAG_RECEIVE_TM;
    }

    void TmModuleDecodexxxPacketRegister (void) {
        tmm_modules[TMM_DECODE_XXX_PACKET].name = "Decodexxx";
        tmm_modules[TMM_DECODE_XXX_PACKET].ThreadInit = DecodexxxThreadInit;
        tmm_modules[TMM_DECODE_XXX_PACKET].Func = Decodexxx;
        tmm_modules[TMM_DECODE_XXX_PACKET].ThreadExitPrintStats = NULL;
        tmm_modules[TMM_DECODE_XXX_PACKET].ThreadDeinit = NULL;
        tmm_modules[TMM_DECODE_XXX_PACKET].RegisterTests = NULL;
        tmm_modules[TMM_DECODE_XXX_PACKET].cap_flags = 0;
        tmm_modules[TMM_DECODE_XXX_PACKET].flags = TM_FLAG_DECODE_TM;
    }

将这些函数 export 到 `src/suricata.c` 中：

    /* new-packet */
    TmModuleRecivexxxPacketRegister();
    TmModuleDecodexxxPacketRegister();

有时候某些 capture mode 会被禁用，此时其注册函数通常返回一个警告信息，以说明其没有内置该 capture mode 支持。

# 源码阅读

* 注册包解析器: main -> PostConfLoadedSetup -> AppLayerDetectProtoThreadInit -> RegisterAppLayerParsers
