## 问题记录

1. 感觉用rails挺麻烦。。不如直接用php
2. js中`document.getElementById("f_phone").onfocus=stop_refresh;`只能用函数名，不能加括号
3. js刷新页面和停止刷新页面的方法

```

var t;
function start_refresh() { 
   location.assign(location.href);
} 
function stop_refresh(){
  clearTimeout(t);
}

function autoref(){
  t=setTimeout('start_refresh()',2000); 
}

```

4. 如果`bundle install`时，提示SSL错误什么的，可以把Gemfile里的`source 'https://rubygems.org`换成`source 'http://rubygems.org'`
5. 用ruby193，当提示xxx时，将application.js里最后两行去掉

```

//= require turbolinks
//= require_tree .

```

6. ruby中的字符编码问题，参考https://ruby-china.org/topics/16856。 将bytes转换成文字，用`byte.to_a.pack('c*').force_encoding('gbk')`
7. 数据库文件sqlit3，不能动。sublime会将它显示并且可以二进制打开，看不能能隐藏掉这种文件
8. `SQLite3::Database.new(xxx)` xxx貌似不能写路径