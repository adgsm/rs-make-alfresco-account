package rs.make.alfresco.account;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScript;
import org.springframework.extensions.webscripts.WebScriptRequest;

import com.google.gson.Gson;

import rs.make.alfresco.common.message.MakeMessage;
import rs.make.alfresco.common.status.MakeStatus;
import rs.make.alfresco.common.webscripts.MakeCommonHelpers;

public class GetAuthenticatedUser extends DeclarativeWebScript {

	protected MakeStatus makeStatus;
	public MakeStatus getMakeStatus() {
		return makeStatus;
	}
	public void setMakeStatus( MakeStatus makeStatus ) {
		this.makeStatus = makeStatus;
	}

	protected MakeCommonHelpers makeCommonHelpers;
	public MakeCommonHelpers getMakeCommonHelpers() {
		return makeCommonHelpers;
	}
	public void setMakeCommonHelpers( MakeCommonHelpers makeCommonHelpers ) {
		this.makeCommonHelpers = makeCommonHelpers;
	}

	protected PersonService personService;
	public PersonService getPersonService() {
		return personService;
	}
	public void setPersonService( PersonService personService ) {
		this.personService = personService;
	}

	protected NodeService nodeService;
	public NodeService getNodeService() {
		return nodeService;
	}
	public void setNodeService( NodeService nodeService ) {
		this.nodeService = nodeService;
	}

	protected AuthorityService authorityService;
	public AuthorityService getAuthorityService() {
		return authorityService;
	}
	public void setAuthorityService( AuthorityService authorityService ) {
		this.authorityService = authorityService;
	}

	private final String AUTHORITIES_NAME = "authorities";
	private final QName AUTHORITIES = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , AUTHORITIES_NAME );
	private final String ORGANISATIONS_NAME = "organisations";
	private final QName ORGANISATIONS = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , ORGANISATIONS_NAME );

	private final String AUTHORITY_NAME = "authority-name";
	private final String AUTHORITY_DISPLAY_NAME = "authority-display-name";

	private final String ORGANISATION_FILTER = "organisation--";
	private final String[] SUFIXES = {};

	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;

	private static Logger logger = Logger.getLogger( GetAuthenticatedUser.class );

	@SuppressWarnings("unchecked")
	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			String authenticatedUserName = AuthenticationUtil.getFullyAuthenticatedUser();

			NodeRef person = personService.getPerson( authenticatedUserName );
			if( person == null ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( authenticatedUserName );
				String errorMessage = message.get( "error.personDoesNotExist" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			JSONArray authorities = new JSONArray();
			AuthenticationUtil.setRunAsUserSystem();

			Set<String> auths = authorityService.getAuthoritiesForUser( authenticatedUserName );
			for( String authName : auths ){
				JSONObject authObj = new JSONObject();
				authObj.put( AUTHORITY_NAME , authName );
				authObj.put( AUTHORITY_DISPLAY_NAME , authorityService.getAuthorityDisplayName( authName ) );
				authorities.add( authObj );
			}

			ArrayList<String> organisations = makeCommonHelpers.getFilteredUserTags( authenticatedUserName , ORGANISATION_FILTER , SUFIXES );

			AuthenticationUtil.setRunAsUser( authenticatedUserName );

			Map<QName, Serializable> properties = nodeService.getProperties( person );
			properties.put( AUTHORITIES , authorities );
			properties.put( ORGANISATIONS , organisations );

			Gson gson = new Gson();
			model.put( "response", gson.toJson( properties ) );
			ArrayList<String> args = new ArrayList<String>(1);
			args.add( authenticatedUserName );
			String parsedMessage = message.get( "success.text" , args );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + GetAuthenticatedUser.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + GetAuthenticatedUser.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + GetAuthenticatedUser.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + GetAuthenticatedUser.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + GetAuthenticatedUser.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , GetAuthenticatedUser.class );
			return null;
		}
		return model;
	}
}
