<#compress>
{
	"status": {
		"code" : 200,
		"name" : "OK",
		"description" : <#if success??>"${ success }"<#else>""</#if>
	},
	"message" : {
		"response" : <#if response??>${ response }<#else>null</#if>
	}
}
</#compress>