# L4D2 Split Pack Attack Warn Plugin(linux only)
> 本插件已经集成了***葈㤀(qq1047504736)***的修复, 感谢大佬无私提供思路与接口. 
* * * 
基于[SMTP Mail Plugin](https://github.com/Miuwiki/SMTP-mail-plugin)提供的api 制作的告警插件 
警示服务器正在遭受小包攻击.

* * * 
## Convar: 

```sourcepawn
cvar_waringinterval = CreateConVar("l4d2_splitattack_waringinterval", "1", "每次邮件警告间隔多少分钟", FCVAR_PROTECTED, true, 10.0);
cvar_attackcheckcount = CreateConVar("l4d2_splitattack_maxcount", "20", "每秒最多接受多少次split count处理.", FCVAR_PROTECTED, true, 0.0);
cvar_smtphost = CreateConVar("l4d2_smtp_host", "smtp.qq.com", "SMTP 服务器域名/ip", FCVAR_PROTECTED);
cvar_smtpport = CreateConVar("l4d2_smtp_port", "465", "SMTP 服务器端口", FCVAR_PROTECTED, true, 1.0, true, 65535.0);
cvar_smtpencryption = CreateConVar("l4d2_smtp_encryption", "2", "SMTP 服务器加密协议. 0 = 不适用加密, 1 = 自动, 2 = SSL", _, true, 0.0, true, 2.0);
cvar_verifyhost = CreateConVar("l4d2_smtp_verifyhost", "2", "如果启用加密, 是否确认服务器的证书有效性. 0 = 不确认, 其余为拓展的确认方式, 不清楚请勿改动.", _, true, 0.0);
cvar_verifypeer = CreateConVar("l4d2_smtp_verifypeer", "0", "如果启用加密, 是否确认服务器返回的数据. 0 = 不确认, 其余为拓展的确认方式, 不清楚请勿改动.", _, true, 0.0);
cvar_verbose = CreateConVar("l4d2_smtp_verbose", "0", "是否开启curl 的 debug 调试", _, true, 0.0);
cvar_smtpusername = CreateConVar("l4d2_smtp_username", "", "SMTP 服务器的用户名", FCVAR_PROTECTED);
cvar_smtppassword = CreateConVar("l4d2_smtp_password", "", "SMTP 服务器的用户密码", FCVAR_PROTECTED);
cvar_smtpreciver = CreateConVar("l4d2_smtp_reciver", "", "需要发送给哪些邮箱, 每个邮箱都需要用\",\"结尾", FCVAR_PROTECTED);
```

* * *
## 注意: 
+ 目前暂时只支持 linux 服务器, 因为目前 curl 拓展只有linux版本的. 
+ 不会自动生成.cfg配置文件, 请手动更改源码内的cvar 或者写在server.cfg中.
+ 请注意curl拓展是否生效, curl拓展兼容性非常不行, 不同linux的发行版本和不同的gcc都会导致curl拓展不一定生效
+ curl拓展不生效请在控制台输入 sm exts load curl 检查不生效原因, 并自行查找解决办法.
+ 请务必确认填写的邮箱以及密码是否正确.