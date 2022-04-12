global iptable:table[addr] of set[string]=table();
event http_header(c: connection, is_orig:bool, name:string, value: string)
{
if(c$id$orig_h in iptable)
{
add iptable[c$id$orig_h][c$http$user_agent];
}
else
{
iptable[c$id$orig_h]=set(c$http$user_agent);
}
if(|iptable[c$id$orig_h]|>=3)
{
print fmt("%s is a proxy",c$id$orig_h);
}
}
