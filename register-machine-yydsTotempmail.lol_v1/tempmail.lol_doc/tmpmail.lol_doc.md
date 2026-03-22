入门
欢迎使用 TempMail 开发者 API。我们有一些很棒的功能，例如...

免费层级无需 API 密钥注册
Plus 和 Ultra 用户的自定义域
还有更多！查看我们的 价格页面 了解更多信息。
如果不使用库，所有的POST请求必须将Content-Type头设置为application/json！

选择您的库




pip3 install tempmail-lol
API 类型
邮件
一个邮件对象，当您检查您的收件箱时返回。

名称	类型	描述
from	string	邮件发送者
to	string	接收者（您的临时邮箱）
subject	string	邮件主题
body	string	纯文本正文，可能为空
html	?string	邮件 HTML（可能为空）
date	number	接收邮件时的 Unix 时间戳
收件箱
一个收件箱对象，包含邮箱地址和访问令牌。

名称	类型	描述
address	string	创建的邮箱地址
token	string	查看收件箱的访问令牌
收件箱生命周期
收件箱的生命周期取决于您的订阅层级。

订阅层级	生命周期
免费（无订阅）	一小时
TempMail Plus	十小时
TempMail Ultra	三十小时
收件箱生命周期可以通过重新请求创建收件箱方法延长（仅适用于自定义域）。

创建收件箱
创建收件箱方法可以使用 GET 或 POST。POST 方法允许您自定义选项，例如收件箱的前缀和域。

GET 方法目前仅存在于遗留原因。

POST /v2/inbox/create
from TempMail import TempMail
tmp = TempMail("optional-api-key")

inb = tmp.createInbox()

# Or... use a prefix
inb = tmp.createInbox(prefix = "joe")

# You can use a setup custom domain here
inb = tmp.createInbox(domain = "mycustomdomain.com", prefix = "optional")
正文
参数	类型	描述	默认
domain	?string	收件箱的域，或随机。可以是自定义域。	null
prefix	?string	收件箱的前缀，或随机。	null
响应 (201)
名称	类型	描述
address	string	收件箱的邮箱地址。
token	string	收件箱的令牌。
获取邮件
使用创建邮箱时收到的令牌获取邮件。如果您丢失了令牌，您将无法再访问邮件，除非是自定义域（请不要为此联系支持，我们无法出于法律原因给您邮箱地址）。

GET /v2/inbox
from TempMail import TempMail
tmp = TempMail("optional-api-key")

inb = tmp.createInbox()

emails = tmp.getEmails(inb.token)

print("Emails:")

for email in emails:
    print("\tSender: " + email.sender)
    print("\tRecipient: " + email.recipient)
    print("\tSubject: " + email.subject)
    print("\tBody: " + email.body)
    print("\tHTML: " + str(email.html)) # may be None
    print("\tDate: " + str(email.date)) # Unix timestamp in milliseconds

查询
参数	类型	描述	默认
token	string	访问收件箱的令牌	null
响应 (200)
名称	类型	描述
emails	Email[]	从服务器接收到的邮件数组
expired	boolean	如果收件箱过期为真（见收件箱生命周期）
准备自定义域
在 TempMail 上使用自定义域之前，您必须设置一些记录。建议在账户页面进行，但您也可以通过 API 进行。

使用自定义域需要 TempMail Plus 或 Ultra 订阅。

POST /v2/custom
正文
参数	类型	描述	默认
domain	string	在 TempMail 上注册的域	null
Response (200)
名称	类型	描述
uuid	string	为您的域记录设置的 UUID（见下文）
在您的域下添加此记录为[uuid].yourdomain.com，并将值设置为tm-custom-domain-verification。

如果您使用子域，请设置为[uuid].subdomain.yourdomain.com。

响应 (4xx)
名称	类型	描述
error	string	解释为何无法设置域的错误。
创建自定义域地址
与创建普通收件箱的方式相同，使用您的域创建自定义域收件箱！

注意事项：

必须使用创建域的UUID时使用的相同账户
prefix参数将设置为无前导数字的普通前缀
POST /v2/inbox/create
from TempMail import TempMail
tmp = TempMail("API Key required for custom domains")

inb = tmp.createInbox()

inb = tmp.createInbox(domain = "mycustomdomain.com", prefix = "optional")
正文
参数	类型	描述	默认
domain	string	您的自定义域。	null
prefix	?string	收件箱的邮箱地址（@之前的部分），或随机。	null
响应 (201)
名称	类型	描述
address	string	收件箱的邮箱地址。
token	string	收件箱的令牌。
如果您丢失了收件箱的令牌，请使用相同的前缀再次调用该方法。收件箱的生命周期将根据您的订阅延长。您可以无限次延长。

使用获取邮件的方法检查收件箱。

私有 Webhooks
设置私有 webhooks，以便您域的所有邮件直接发送到您的 webhook。

需要有效的 TempMail Ultra 订阅。

您必须已经为自定义域设置好域（[uuid].domain.com）。

POST /v2/private_webhook
Body
参数	类型	描述	默认
domain	string	设置 webhook 的域	null
url	string	邮件将转发到的 webhook URL	null
响应 (200)
名称	类型	描述
success	true	总是为真
message	string	成功信息消息
响应 (4xx)
名称	类型	描述
error	string	包含错误详细信息的消息
您还可以使用域作为查询参数 DELETE /private_webhook 来删除它。

标准 Webhooks
在您创建的每个标准邮箱上设置标准 webhooks。邮件将转发到您的 webhook。

需要有效的 TempMail Ultra 订阅。

这不会追溯应用于现有邮件。

POST /v2/webhook
正文
参数	类型	描述	默认
url	string	邮件将转发到的 webhook URL	null
响应 (200)
名称	类型	描述
success	true	总是为真
响应 (4xx)
名称	类型	描述
error	string	包含错误详细信息的消息
您还可以使用 DELETE /webhook 从您的账户中删除它。