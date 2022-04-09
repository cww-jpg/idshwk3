global iptable:table[addr] of set[string]=table();
event http_reply(c: connection, version: string, code: count, reason: string)
{
if(c$id$orig_h in iptable)
{
add iptable[c$id$orig_h][c$http$user_agent];
if(|iptable[c$id$orig_h]|>=3)
print c$id$orig_h;
print " is a proxy";
}
}
event zeek_done()
{
print "hello world";
}
