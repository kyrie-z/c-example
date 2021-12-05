# File

## extend attr(EA)
扩展属性包含四类：**user, trusted, system. security** \

设置文件扩展属性：
```
setfattr -n user.hash -v 39df54e93 filename
```

查看文件扩展属性：
```
gtfattr -d filename
```

删除文件扩展属性：
```
setfattr -x user.hash filename
```
