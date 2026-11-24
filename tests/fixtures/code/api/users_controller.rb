User.where("name = '#{params[:name]}'")
User.where(name: params[:name])
system("convert #{params[:file]} out.png")
obj = Marshal.load(data)
<%= raw @comment.body %>
obj = YAML.unsafe_load(data)
obj = Marshal.restore(data)
obj = YAML.safe_load(data)
