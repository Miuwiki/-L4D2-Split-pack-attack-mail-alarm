#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>
#include <dhooks>
#include <miuwiki_smtptools>
#include <splitattackcount>

#define PLUGIN_VERSION "1.0.0"

ConVar
	cvar_waringinterval,
	cvar_attackcheckcount,
	cvar_smtphost,
	cvar_smtpport,
	cvar_smtpencryption,
	cvar_verifyhost,
	cvar_verifypeer,
	cvar_verbose,
	cvar_smtpusername,
	cvar_smtppassword,
	cvar_smtpreciver;

enum struct SMTPINFO
{
	int nextwarningtime;
	int warninginterval;
	int attackcount;
	int checkcount;

	char host[512];
	int  port;
	Encryption encryption;
	int verifyhost;
	int verifypeer;
	int verbose;

	char username[256];
	char password[256];

	ArrayList reciver;
}

SMTPINFO g_smtp;

public Plugin myinfo =
{
	name = "[L4D2] Split Attack Alarm",
	author = "Miuwiki",
	description = "Use mail to alarm server owner that server is attacked.",
	version = PLUGIN_VERSION,
	url = "http://www.miuwiki.site"
}

public void OnAllPluginsLoaded()
{
	if( !LibraryExists("miuwiki_smtptools") )
		SetFailState("Couldn't find request plugin \"miuwiki_smtptools.smx\", check it is running or not.");
	
	if( !LibraryExists("miuwiki_splitattackcount") )
		SetFailState("Couldn't find request plugin \"miuwiki_smtptools.smx\", check it is running or not.");
}

public void OnPluginStart()
{
	g_smtp.reciver = new ArrayList(ByteCountToCells(512));

	RegConsoleCmd("sm_status", Cmd_Status);

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
	cvar_smtpreciver.AddChangeHook(Hook_CvarChange);
}

public void OnMapStart()
{
	CreateTimer(1.0, Timer_CheckAttack, _, TIMER_FLAG_NO_MAPCHANGE|TIMER_REPEAT);
}

public void OnConfigsExecuted()
{
	char buffer[512];

	cvar_smtphost.GetString(buffer, sizeof(buffer));
	FormatEx(g_smtp.host, sizeof(g_smtp.host), "%s", buffer);

	g_smtp.warninginterval = cvar_waringinterval.IntValue;
	g_smtp.checkcount 	   = cvar_attackcheckcount.IntValue;
	g_smtp.port       	   = cvar_smtpport.IntValue;
	g_smtp.encryption 	   = view_as<Encryption>(cvar_smtpencryption.IntValue);
	g_smtp.verifyhost 	   = cvar_verifyhost.IntValue;
	g_smtp.verifypeer 	   = cvar_verifypeer.IntValue;
	g_smtp.verbose    	   = cvar_verbose.IntValue;

	cvar_smtpusername.GetString(buffer, sizeof(buffer));
	FormatEx(g_smtp.username, sizeof(g_smtp.username), "%s", buffer);

	cvar_smtppassword.GetString(buffer, sizeof(buffer));
	FormatEx(g_smtp.password, sizeof(g_smtp.password), "%s", buffer);

	g_smtp.reciver.Clear();
	cvar_smtpreciver.GetString(buffer, sizeof(buffer));

	StoreMailRecipent();
}

void Hook_CvarChange(ConVar convar, const char[] oldValue, const char[] newValue)
{
	g_smtp.reciver.Clear();
	StoreMailRecipent();
}

void MailSendResult(int code, const char[] message)
{
	if( code != SEND_SUCCESS )
	{
		LogError(message);
		return;
	}

	LogMessage(message);
}

Action Cmd_Status(int client, int args)
{
	if( client < 1 || client > MaxClients || !IsClientInGame(client) || IsFakeClient(client) )
		return Plugin_Handled;
	
	char buffer[512],serverinfo[6][256];

	GetServerInfomation(serverinfo, sizeof(serverinfo), sizeof(serverinfo[]));

	SMTP mail = new SMTP(g_smtp.host, g_smtp.port);
	mail.SetVerify(g_smtp.encryption, g_smtp.verifyhost, g_smtp.verifypeer);
	mail.SetSender(g_smtp.username, g_smtp.password);
	mail.SetTitle("你的L4D2服务器正遭受Split Pack攻击");
	for(int i = 0; i < sizeof(serverinfo); i++)
	{
		mail.AppendInfo(serverinfo[i]);
	}

	for(int i = 0; i < g_smtp.reciver.Length; i++)
	{
		g_smtp.reciver.GetString(i, buffer, sizeof(buffer));
		mail.AddRecipient(buffer);
	}
	mail.Send(MailSendResult);

	return Plugin_Handled;
}

Action Timer_CheckAttack(Handle timer)
{
	if( g_smtp.attackcount >= g_smtp.checkcount )
	{
		if( GetTime() >= g_smtp.nextwarningtime )
		{
			SendWarningMail();
			g_smtp.nextwarningtime = GetTime() + g_smtp.warninginterval * 60;
			LogMessage("Catch a split attack, send warning mail to server owner.");
		}
		else
		{
			LogMessage("Catch a split attack, but still in warning cooling time.");
		}
	}

	g_smtp.attackcount = 0;
	return Plugin_Continue;
}

public void M_GetSplitAttack()
{
	g_smtp.attackcount++;
	// LogMessage("get a split attack!");
}

void SendWarningMail()
{
	char buffer[512], serverinfo[6][256];

	GetServerInfomation(serverinfo, sizeof(serverinfo), sizeof(serverinfo[]));

	SMTP mail = new SMTP(g_smtp.host, g_smtp.port);
	mail.SetVerify(g_smtp.encryption, g_smtp.verifyhost, g_smtp.verifypeer);
	mail.SetSender(g_smtp.username, g_smtp.password);
	mail.SetTitle("你的L4D2服务器正遭受Split Pack攻击");
	for(int i = 0; i < sizeof(serverinfo); i++)
	{
		mail.AppendInfo(serverinfo[i]);
	}
	
	for(int i = 0; i < g_smtp.reciver.Length; i++)
	{
		g_smtp.reciver.GetString(i, buffer, sizeof(buffer));
		mail.AddRecipient(buffer);
	}

	mail.Send(MailSendResult);
}

void GetServerInfomation(char[][] info, int length, int size)
{
	if( length < 6 )
		return;

	char buffer[512], temp[7][256], playerstate[2][128];

	ServerCommandEx(buffer, sizeof(buffer), "status");
	ExplodeString(buffer, ": ", temp, sizeof(temp), sizeof(temp[]));

	FormatEx(buffer, strlen(temp[1]) - 7, "%s", temp[1]); // strlen("version") = 7
	Format(buffer, sizeof(buffer), "服务器: %s", buffer);
	strcopy(info[0], size, buffer);

	FormatEx(buffer, strlen(temp[2]) - 7, "%s", temp[2]); // strlen("udp/ip ") = 7
	Format(buffer, sizeof(buffer), "版本: %s", buffer);
	strcopy(info[1], size, buffer);

	FormatEx(buffer, strlen(temp[3]) - 7, "%s", temp[3]); // strlen("os     ") = 7
	Format(buffer, sizeof(buffer), "ip信息: %s", buffer);
	strcopy(info[2], size, buffer);

	FormatEx(buffer, strlen(temp[4]) - 7, "%s", temp[4]); // strlen("map     ") = 7
	Format(buffer, sizeof(buffer), "服务器类型: %s", buffer);
	strcopy(info[3], size, buffer);

	FormatEx(buffer, strlen(temp[5]) - 7, "%s", temp[5]); // strlen("players ") = 7
	Format(buffer, sizeof(buffer), "当前地图: %s", buffer);
	strcopy(info[4], size, buffer);

	ExplodeString(temp[6], "#", playerstate, sizeof(playerstate), sizeof(playerstate[]));
	FormatEx(buffer, sizeof(buffer), "玩家信息: %s", playerstate[0]); 
	strcopy(info[5], size, buffer);
}


void StoreMailRecipent()
{
	char buffer[512];
	cvar_smtpreciver.GetString(buffer, sizeof(buffer));

	char mail[256]; int split;
	do
	{
		if( IsNullString(buffer) )
			break;
		
		split = SplitString(buffer, ",", mail, sizeof(mail));

		if( split == -1 )
			break;
		
		g_smtp.reciver.PushString(mail);
		Format(buffer, sizeof(buffer), "%s", buffer[split]);

		LogMessage("store recipient %s", mail);
	}
	while( split != -1 );
}