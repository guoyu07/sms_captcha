
class MsgsController < ApplicationController
  before_action :set_msg, only: [:show, :edit, :update, :destroy]

  # GET /msgs
  # GET /msgs.json
  def index
    refresh
    @msgs = Msg.where("vpnip LIKE '#{@filter.f_vpnip}' and phone LIKE '#{@filter.f_phone}' and sms LIKE '#{@filter.f_user}'")
  end



  # GET /msgs/1
  # GET /msgs/1.json
  def show
  end

  def refresh
    @filter = Filter.new(params[:f_vpnip], params[:f_phone], params[:f_user])
  end

  # GET /msgs/new
  def new
    @msg = Msg.new
  end

  # GET /msgs/1/edit
  def edit
  end

  # POST /msgs
  # POST /msgs.json
  def create
    @msg = Msg.new(msg_params)

    respond_to do |format|
      if @msg.save
        format.html { redirect_to @msg, notice: 'Msg was successfully created.' }
        format.json { render :show, status: :created, location: @msg }
      else
        format.html { render :new }
        format.json { render json: @msg.errors, status: :unprocessable_entity }
      end
    end
  end

  # PATCH/PUT /msgs/1
  # PATCH/PUT /msgs/1.json
  def update
    respond_to do |format|
      if @msg.update(msg_params)
        format.html { redirect_to @msg, notice: 'Msg was successfully updated.' }
        format.json { render :show, status: :ok, location: @msg }
      else
        format.html { render :edit }
        format.json { render json: @msg.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /msgs/1
  # DELETE /msgs/1.json
  def destroy
    @msg.destroy
    respond_to do |format|
      format.html { redirect_to msgs_url, notice: 'Msg was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_msg
      @msg = Msg.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def msg_params
      params.require(:msg).permit(:vpnip, :vpnmac, :phone, :sms)
    end
end
