class Filter < ActiveRecord::Base
  attr_accessor :f_vpnip, :f_phone, :f_user
  def initialize(vpnip, phone, user)
    @f_vpnip = "%" + vpnip.to_s + "%"
    @f_phone = "%" + phone.to_s + "%"
    @f_user = "%" + user.to_s + "%"
  end
end
