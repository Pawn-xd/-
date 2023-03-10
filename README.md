

#   熊猫烧香



## 基本信息

- 报告名称：熊猫烧香病毒报告
- 作者：Pawn
- 文件名：xiongmao.exe
- 样本类型：EXE文件
- 样本文件大小：30,001 字节
- 样本文件的MD5校验值：512301c535c88255c9a252fdf70b7a03
- 样本文件SHA1校验值：ca3a1070cff311c0ba40ab60a8fe3266cfefe870
- 壳信息：FSG 2.0
- 相关漏洞：弱密码

##  基础动静态分析

###  PEiD信息

###  ![PEiD信息](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\PEiD信息.png)

程序加了壳，壳为FSG 2.0

###  脱壳

使用OllyDBG插件 OllyDump可以轻松找到OEP为 0040D278，使用ImpREC修复注册表发现只有kernal32.dll，可能是自动修复导入表失败

所以查看脱壳存根构建的IAT

根据FSG2.0壳的特点 搜索`JMP DWORD PTR DS:[EBX+0xC]` 指令（一般为跳转OEP指令），设置断点，向上寻找LoadLibrary和GetProcAddress函数。

![IAT构建](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\IAT构建.png)

可以看到 导入表 不同库函数之间被填充为了7FFFFFFF，导致自动修复IAT失败。所以将7FFFFFFF填充为00000000。使用OllyDump脱壳修复导出表

###  导入表函数

使用Dependency walker查看导入表函数

![导入表函数](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\导入表函数.png)

KERNEL32.DLL中导入了关于文件读写的API函数，猜测病毒创建了文件，并写入。

ADVAPI.DLL中导入了关于注册表操作的相关API函数，猜测病毒修改了注册表

WS2_32.DLL和WININET.DLL提供了与网络操作相关的API函数，猜测函数连接外部网络



###  基础动态分析

使用windows xp（service pack3）系统兼容模式启动

**发现恶意代码关闭了安全中心服务**

![关闭安全防护服务](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\关闭安全防护服务.png)

**运行后发现多了一个进程spo01sv.exe** 

![进程信息](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\进程信息.png)



在C:\Windows\System32\drivers\目录下，创建了spo0lsv.exe

查看spo0lsv的md5值，发现和xiongmao.exe相等，所以推测病毒将xiongmao.exe复制到此目录下

<img src="C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\创建文件.png" alt="创建文件" style="zoom: 67%;" />

使用regshot工具对比运行前后的注册表变化（详见/熊猫烧香分析报告.asset/运行前后注册表对比.txt）

- **注册表删除的键**：

  ![注册表键删除](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\注册表键删除.png)

  此注册表键代表了windows的安全防护服务，恶意代码关闭了windows的安全防护服务

- **注册表添加的键**：

  ![注册表添加的键](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\注册表添加的键.png)

  Tracing键是跟踪日志和跟踪文件的路径、文件名和其他设置。

- **注册表添加的键值**：

  ![注册表添加键值](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\注册表添加键值.png)


恶意代码设置`HKU\S-1-5-21-3607991960-4000027800-3246950079-1000\Software\Microsoft\Windows\CurrentVersion\Run\svcshare`键值为`"C:\Windows\system32\drivers\spo0lsv.exe"` 添加了自启动功能



- **注册表删除的键值**

  ![注册表删除键值](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\注册表删除键值.png)

可以看到spo0lsv.exe尝试删除了很多自启动项，通过检索这些名称，推测为恶意代码会删除和杀毒软件相关得自启动项

Internet Settings应该是浏览器的一些信息

###  文件操作

- 恶意代码创建了大量的desktop_.ini文件，里面存储了时间信息
- 恶意代码打开了大量的exe文件，结合观察到的一些文件图标变为“熊猫烧香”的图标，推测为恶意代码便利文件目录并将exe等文件图标改为“熊猫烧香”的图标
- 恶意代码打开了cmd.exe，可能执行了一些命令

![打开cmd](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\打开cmd.png)



###  网络操作

![网络操作](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\网络操作.png)

查看网络操作可以看到，因为本机的ip地址为192.168.40.129所以可以看到恶意代码尝试连接局域网的其他主机。

###  进程和线程信息

只看到恶意代码创建了一些线程，没有特别有用的信息

###  其他

尝试打开任务管理器和注册表闪退，推测恶意代码阻止用户打开windows自带的工具

###  总结

- 恶意代码首先将自身复制到系统C:\Windows\System32\drivers\目录下，并设置了自启动注册表键值
- 恶意代码关闭了安全防护的服务
- 恶意代码将杀毒软件的开机启动键值删除
- 恶意代码阻止用户打开任务管理器和注册表等
- 恶意代码连接局域网
- 恶意代码遍历文件系统，将一些文件的图标改为“熊猫烧香”图标，如exe文件，每个目录下创建desktop_.ini文件，记录时间信息
- 恶意代码创建了关于自身运行的相关注册表键

##  详细分析

###  静态分析设置和技巧

首先脱壳后发现恶意代码是使用Delphi 6.0-7.0编写的恶意代码，Delphi使用fastcall调用约定，但是与Windows的fastcall略有不同，参数顺序为eax为第一个参数、edx为第二个参数、ecx为第三个参数，大于3个的参数通过堆栈传递，大于三个的堆栈顺序从左到右依次压栈，堆栈由被调用者恢复。我们使用IDR和IDA PRO对此恶意代码进行反汇编分析。

对ida进行一些设置：

- Options–>Compiler:Compiler（Delphi）、Calling convention(FastCall)
- View–>Open Subviews–>Signatures–>Apply new Signatures:选择delphi相关Signatures

###  恶意代码初始化

![初始化操作](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\初始化操作.png)

程序开始OEP调用了InitExe和LStrAsg函数，应为一些初始化函数。

####  解码

![00405250](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\00405250.png)

函数有三个参数并将40D8A0处的数据，xboy，第一个局部变量。

进入00405250分析

![405250](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\IDA_405250.png)

![ollydbg_405250](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\ollydbg_405250.png)

结合Ollydbg和IDA分析，此函数为解密函数，将“xboy”和“'\"++戊+缓\"叛*聋+肛+删\"蚊*苜+兆++*'”以某种顺序取字符异或，解密

![字符串对比-跳转](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\字符串对比-跳转.png)

解密后的字符串与\*武\*汉\*男\*生\*感\*染\*下\*载\*者\*  对比，相同则跳转，不同则退出。然后继续解密，对比，相同则跳转，不同则退出

![病毒主函数调用](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\病毒主函数调用.png)

综合查看start中所有流程，图中的三个call应该为病毒的主功能调用。我们先进入sub_40819C分析

###    主体功能函数 一

####  删除Desktop_.ini文件

![判断ini文件是否存在](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\判断ini文件是否存在.png)

首先判断通过程序的目录，查看目录下Desktop_.ini文件是否存在。有则执行

![存在的行为](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\存在的行为.png)

存在Desktop_.ini文件，则会更改文件属性为NORMAL，然后删除 Desktop\_.ini



####  判断是否为被感染的程序

![写入PE文件跳转](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\写入PE文件跳转.png)

这一段代码内容一直没搞明白是什么内容，直到看到下图的的分支，我测试了源程序和C:\Windows\System32\drivers\spo0lsv.exe函数的分支都没有实现跳转，然后我测试了被感染文件的这个判断，发现执行了跳转，然后测试前面的程序的数据流，明白了Writre_PE_Dictionary函数的作用



![感染与否分支](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染与否分支.png)

被感染程序的特征码为类似

![Chrome特征码](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\Chrome特征码.png)

![WireShark特征码](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\WireShark特征码.png)

其实感染特征码为==WhoBoy+程序名+.exe+2+源文件大小+1==



####  判断是否为C:\Windows\system32\drivers\spo0lsv.exe

![对比程序路径与系统目录](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\对比程序路径与系统目录.png)

将程序绝对地址转换为大写字符，然后与系统根目录路径cat上drivers\\spo0lsv.exe（本系统为C:\Windows\System32）对比，然后有两条执行路径。

根据先前的基础分析，我们猜测

​	如果程序不是drivers\spo0lsv.exe则可能复制文件到此处，再运行；

​	如果程序是drivers\spo0lsv.exe则可能执行我们基础分析的相关功能；

####  不是感染文件且不是\spo0lsv.exe程序

![复制文件](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\复制文件.png)

首先判断系统是否纯在spo0lsv.exe进程，有则结束掉进程，然后复制spo0lsv.exe到C:\Windows\System32\\drivers\\目录下并运行。

查看C:\Windows\System32\driver目录下，发现了spo0lsv.exe函数验证猜想

其中@Judge_process_kill程序分析流程如下

![判断进程并关闭进程](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\判断进程并关闭进程.png)

将SPO0LSV.EXE与循环取出进程名对比，去除进程名有关的API函数为CreateToolhelp32Snapshot、Process32First、Process32Next等函数

然后改为分析系统目录下的spo0lsv.exe文件跳转到另一个分支，这个分支会和感染程序的分支汇合形成另一个分支

![感染与否分支](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染与否分支.png)

####  是dirvers\spo0lsv.exe

​	右边的分支直接清栈返回

####  是感染文件

![第一个函数左分支0](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第一个函数左分支0.png)

![第一个函数左分支1](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第一个函数左分支1.png)

![第一个函数左分支2](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第一个函数左分支2.png)

感染后的文件由 ==病毒文件+原文件+感染特征值== 组成。所以我们分析程序可知程序将原文件复制到一个新文件中，新文件与感染后的文件有相同的属性

之后，病毒在C:\Users\Pawn\AppData\Local\Temp下生成批处理块,格式为“数字+$$“，内容如下

`:try1
del "源程序绝对地址"
if exist "源程序绝对地址" goto try1
ren "源程序绝对地址+后缀名" "源程序名称"
if exist "源程序绝对地址+后缀名" goto try2
"源程序绝对地址"
:try2
del %0`

具体作用为

- 删除位于 "源程序绝对地址" 的文件。
- 如果文件被成功删除，执行下一步操作；如果删除失败，跳转到标签 ":try1" 重新执行删除操作。
- 将 "源程序绝对地址+后缀名" 重命名为 "源程序名称"。
- 如果重命名成功，执行下一步操作；如果重命名失败，跳转到标签 ":try2" 删除当前脚本文件。
- 启动 "源程序"。
- 删除当前脚本文件。

这条分支的作用是如果只是表面杀死病毒没有将所有文件恢复，运行未恢复的文件就会再次感染。

###  主体功能函数 二 

![第二个函数主体功能](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个函数主体功能.png)

####  第一个call，创建线程,本地感染

![创建线程感染本地文件](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\创建线程感染本地文件.png)

线程其实地址为 sub_40A48C

##### 

![排出A和B盘符](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\排出A和B盘符.png)

将盘符转化为字符串，遍历盘符，排除A和B盘符

![感染其他盘符下的文件](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染其他盘符下的文件.png)

#####  Infect函数分析

如果为目录文件则判断目录名称，以排除一些名称

![Windows目录](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\Windows目录.png)

![WINNT目录](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\WINNT目录.png)

排除WINDOWS、WINNT、system32、Documents and Settings 、 System Volume Information 、Recycled  、 Windows NT 、 WindowsUpdate 、Windows Media Player 、 Outlook Express、Internet Explore 、 NetMeeting 、Common Files 、Complus Applications 、Common Files 、 Messenger 、InstallShield Installation Information等目录

![判断是否感染](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\判断是否感染.png)

判断Desktop_.ini文件是否存在来判断是否感染

不存在则创建Desktop_.ini

![创建Desktop_.ini](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\创建Desktop_.ini.png)

写入日期

![写入日期](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\写入日期.png)

存在则更新日期

![更新日期](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\更新日期.png)

如果为普通文件，则先判断是不是GHO文件

![GHO文件删除](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\GHO文件删除.png)

判断是不是GHO文件，如果为GHO文件则删除

然后

![判断跳过感染的文件](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\判断跳过感染的文件.png)

判断是不是setup.exe或者NTDETECT.COM文件，是则跳过

然后判断感染文件类型

![判断感染文件类型](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\判断感染文件类型.png)

程序会判断后缀名是否为EXE、SCR、PIF、COM文件，是的话则执行Infect_file函数感染

进入Infect_file函数

​	![感染文件-判断](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染文件-判断.png)



首先判断程序是否在执行，执行中退出，然后判断文件是否为病毒自身，如果为自身退出；然后将原文件和爆破字典写入内存以便感染，然后判断是否已经感染，如果已经感染则退出

否则执行感染过程

![复制病毒本体](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\复制病毒本体.png)

![感染文件-连接](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染文件-连接.png)

首先复制病毒本体，然后生成感染特征值，连接病毒文件和原文件，再连接感染特征值



判断感染类型

![感染文件-判断1](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染文件-判断1.png)

判断是否为htm、html、asp、php、jsp、aspx

是则执行感染函数Infect_Web_File

![感染网页文件-解码判断](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染网页文件-解码判断.png)

首先将要写入的内容解码，然后判断是否已经感染。

![感染网页文件-连接](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\感染网页文件-连接.png)

然后将上文的内容与\n和\r连接写入网页文件

####  第二个call，使u盘等移动介质可以传播病毒

​	![第二个call-设置定制器函数](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个call-设置定制器函数.png)

设置了一个时间为1770h的ms的计时器，然后执行TimerFunc函数

#####   TimeFunc函数

​	首先也是获得盘符并且跳过A、B盘符

​	![第二个call-跳过ab盘符](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个call-跳过ab盘符.png)

​	然后判断setup.exe文件是否存在

![第二个call-判断setup.exe存在？](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个call-判断setup.exe存在？.png)

不存在则创建，并复制病毒本体到setup.exe

![第二个call-不存在的操作](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个call-不存在的操作.png)

存在则判断是否为病毒文件，不是则删除，并创建setup.exe并复制病毒本体

![第二个call-存在操作](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个call-存在操作.png)

之后判断autorun.inf与setup.exe几乎一致，不过autorun.inf的内容为  `[AutoRun]\r\nOPEN=setup.exe\r\nshellexecute=setup.exe\r\nshell\\Auto\\command=setup.exe\r\n`

之后就是设置文件属性和退出

![第二个call-设置文件属性](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个call-设置文件属性.png)



####  第三个call，连接局域网网络，传播病毒

函数创建了10个线程

![第三个call-创建线程](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个call-创建线程.png)

线程起始地址

![第三个call线程信息](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个call线程信息.png)

动态调试发现 call edx 的edx的值为40BA8C,跳转到 40BA8C查看

![第三个call-功能调用主函数](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个call-功能调用主函数.png)

查看主函数功能

#####  主功能函数

首先查看网络连接状态

![第三个call-网络连接状态](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个call-网络连接状态.png)

尝试感染端口139和445

![第三个call-感染端口](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个call-感染端口.png)

​	连接成功后感染

![第三个call-感染过程](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个call-感染过程.png)

### 主体功能函数 三

函数设置了6个定时器

​	![第三个函数主题](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个函数主题.png)

####  第一个定时器  1s 关闭杀毒软件，注册表添加病毒自启动

![第一个定时器](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第一个定时器.png)

sub_406E2C创建了一个线程，会尝试关闭各种作者列举的杀毒软件和windows安全防护，与基础静态分析相符

第一个定时器比较简单，将C:\\Windows\\System\\dirvers\spo0lsv.exe添加到

- SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run

- SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folde

即设置自启动和添加到受系统保护的文件

####  第二个计时器  1200s 下载文件，可能会二次感染其他病毒

创建的线程首先会冒充qq下载http://www/ac86.cn/66/up.txt

![第二个计时器-冒充qq下载](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个计时器-冒充qq下载.png)

猜测将下载的文件解码然后拼接，运行某程序

![第二个计时器-下载运行](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第二个计时器-下载运行.png)

####  第三个计时器  10s  关闭所有盘符的网络共享

​	创建了2个线程，第一个线程与第二个计时器的功能相同

​	第二个线程为cmd执行命令关闭所有盘符的网络共享

![第三个计时器-关闭共享](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第三个计时器-关闭共享.png)

####  第四个计时器  6s  关闭安全服务，删除一些杀毒软件自启动

第四个计时器关闭了一些服务，删除了一些自启动注册表项，

![第四个计时器-关闭安全服务和删除注册表](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第四个计时器-关闭安全服务和删除注册表.png)

####  第五个计时器  10s  解码一些网站，打开？

解码了一些网站，并下载一些内容？

![第五个计时器-解码网站并下载](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\第五个计时器-解码网站并下载.png)

####  第六个计时器  1800s  下载文件，与二一致

与第二个计时器类似 只不过下载http://update.whboy.net/worm.txt

###  总结

![程序流图](C:\Users\Pawn\Documents\最近的文件\Study\熊猫烧香分析报告.assets\程序流图.png)

##   参考

- delphi中的一些与字符串处理相关的函数：https://www.cnblogs.com/RbtreeLinux/articles/2353454.html
- chatgpt
- https://bbs.kanxue.com/thread-263407.htm#msg_header_h1_3
- https://www.52pojie.cn/thread-1569939-1-1.html
- https://blog.csdn.net/shufac/article/details/52071945
