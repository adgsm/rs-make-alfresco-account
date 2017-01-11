<#compress>
{
	"status": {
		"code" : 200,
		"name" : "OK",
		"description" : <#if success??>"${ success }"<#else>""</#if>
	},
	"message" : {
		"username" : <#if username??>"${ username }"<#else>null</#if>,
		"response" : <#if response??>"${ response }"<#else>null</#if>
	}
}
</#compress>