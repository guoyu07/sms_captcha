require 'rubygems'
require 'ffi/pcap'
require 'socket'
require 'sqlite3'


class Mac
	@byte = nil
	def initialize(arr)
		if (arr.size != 14)
			fail ArgumentError, "Mac string length is #{arr.size} != 14"
		end
		@byte = arr
	end
	def dst
		return Arr.to_mac(@byte[0..5])
	end
	def src
		return Arr.to_mac(@byte[6..11])
	end
	def type
		return Arr.to_string(@byte[12..13])
	end
end

class IP
	@byte = nil
	def initialize(arr)
		if (arr.size != 20)
			fail ArgumentError, "IP string length is #{arr.size} != 20"
		end
		@byte = arr
	end
	def src
		return Arr.to_ip(@byte[12..15])
	end
	def dst
		return Arr.to_ip(@byte[16..19])
	end
end

class TCP
	@byte = nil
	def initialize(arr)
		if (arr.size != 20)
			fail ArgumentError, "TCP string length is #{arr.size} != 20"
		end
		@byte = arr

	end
	def src_port 
		return Arr.to_int(@byte[0..1])
	end
	def dst_port
		return Arr.to_int(@byte[2..3])
	end
	def option_length
		return Arr.to_int(@byte[12..12])/4 - 20
	end
end

class SGIP
	@byte = nil
	@msg_length = nil
	def initialize(arr)
		@byte = arr
		@msg_length = Arr.to_int(@byte[152...156])
	end
	def length
		return Arr.to_int(@byte[0...4])
	end
	def phone_number	
		return Arr.to_char(@byte[63...84]).strip!
	end

	def msg
		return Arr.to_char(@byte[156...(156+@msg_length)])
	end
end


class Arr < Array
	class << self
	def to_mac(byte)
		
		str = ""
		for i in 0...byte.size
			str = str + format("%02x", byte[i])+ ":"
		end
		str = str.chop
		return str
	end
	def to_ip(byte)
		str = ""
		for i in 0...byte.size
			str = str + byte[i].to_s + "."
		end
		str = str.chop
		return str
	end
	def to_int(byte)
		n = 0
		size = byte.size
		s = ""
		for i in 0...size
			s = s + byte[i].to_s(16)
		end
		n = s.to_i(16)
		return n
	end
	def to_string(byte)
		str = ""
		format_str = "%02x"
		
		for i in 0...byte.size
			str = str + format(format_str, byte[i])
		end
		return str
	end

	def to_char(byte)
		str = byte.to_a.pack('c*').force_encoding('gbk')
		return str
	end
end
end


# 这个是选择网卡，在不同的设备上，需要选择不同的网卡
# 先使用 puts FFI::PCap::dump_devices 打印出PC上所有的网卡，然后按选择需要的网卡
puts "Start..."
dev_name = FFI::PCap::dump_devices[0][0]
puts "device: #{dev_name}"

pcap = FFI::PCap::Live.new(:dev => dev_name,
						   :timeout => 1,
						   :promisc => true,
						   :handler => FFI::PCap::Handler)

# 这里需要设置网卡的抓包过滤，src host是VPN的IP地址， dst port是短信网关的端口
pcap.setfilter("dst port 8801")


db = SQLite3::Database.new('development.sqlite3')



# 持续抓包
pcap.loop() do |this,pkt|
  
  # 将抓到的包，转换成fixnum数组
  a = pkt.body.each_byte.to_a
  # 如果包长度小于237，则丢掉
  if (a.size < 237)
  	continue
  end
   puts "got it!"
  # 解析包
  begin 
  	  # 获取MAC信息
	  mac = Mac.new(a[0...14])
	  puts "mac.dst = #{mac.dst}"
	  puts "mac.src = #{mac.src}"
	  puts "mac.type = #{mac.type}"

	  # 获取IP信息
	  ip = IP.new(a[14...34])
	  puts "ip.src = #{ip.src}"
	  puts "ip.dst = #{ip.dst}"

	  # 获取TCP信息
	  tcp = TCP.new(a[34...54])
	  puts "tcp.src_port = #{tcp.src_port}"
	  puts "tcp.dst_port = #{tcp.dst_port}"
	  
	  # 获取SGIP信息
	  sgip = SGIP.new(a[(54+tcp.option_length)...-1])
	  # 这个是SGIP里包含的用户手机号码
	  puts "sgip.phone_number = #{sgip.phone_number}"
	  # 这个是SGIP里包含的短信内容
	  puts "sgip.msg = #{sgip.msg}"

	  # # 使用TCP发送信息，要配置IP和端口
	  # begin
		 #  s = TCPSocket.new("200.200.136.42",6699)
		 #  s.puts "#{sgip.phone_number.strip},#{sgip.msg}"

		 #  s.close
	  # rescue Exception => e
		 #  puts "Error:#{e}"
	  # end
	  total = Time.new.to_i
	  # 将收到的信息，按照VPN.IP-VPN.MAC-Phone-Msg的格式，保存到数据库中
	  #cmd = "insert into msgs values('#{total}', '#{ip.src}', '#{mac.src}', '#{sgip.phone_number}', '#{sgip.msg}', 0, 0)"
	  #puts "cmd = #{cmd}"
	  db.execute("insert into msgs values('#{total}', '#{ip.src}', '#{mac.src}', '#{sgip.phone_number}', '#{sgip.msg}', 0, 0)")
	  # 将数据库中的内容，显示到web页面里，实时刷新
	  sleep(0.1)
	


  rescue Exception => err
  	  puts "error: #{err}"
  	  
  end

  puts "======================="
end