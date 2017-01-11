package rs.make.alfresco.account;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.search.SearchService;
import org.alfresco.service.cmr.security.PersonService;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScript;
import org.springframework.extensions.webscripts.WebScriptRequest;

import rs.make.alfresco.common.message.MakeMessage;
import rs.make.alfresco.common.status.MakeStatus;
import rs.make.alfresco.common.webscripts.MakeCommonHelpers;

public class RemoveAuthentication extends DeclarativeWebScript {

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

	protected SearchService searchService;
	public SearchService getSearchService() {
		return searchService;
	}
	public void setSearchService( SearchService searchService ) {
		this.searchService = searchService;
	}

	private final String USER_ADMIN_AUTHORITY = "user-admins";
	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;
	private final String REQUEST_EMAIL_KEY = "email";

	private final String ORGANISATION_FILTER = "organisation--";
	private final String CONSUMER_SUFIX = "--consumer";
	private final String CONTRIBUTOR_SUFIX = "--contributor";
	private final String COORDINATOR_SUFIX = "--coordinator";
	private final String[] SUFIXES = { CONSUMER_SUFIX , CONTRIBUTOR_SUFIX , COORDINATOR_SUFIX };

	private final String DEFAULT_ATTRIBUTE = "DEFAULT";
	private final String DEFAULT_ORGANISATIONS_ATTRIBUTE = "organizations";
	private final String PROPERTY_KEY = "property";
	private final String CONTAINER_KEY = "container";

	private static Logger logger = Logger.getLogger( RemoveAuthentication.class );

	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			String authenticatedUserName = AuthenticationUtil.getFullyAuthenticatedUser();

			AuthenticationUtil.setRunAsUserSystem();

			String email = makeCommonHelpers.getString( req , REQUEST_EMAIL_KEY , message , status , true );

			ArrayList<NodeRef> organisationNodes = new ArrayList<NodeRef>();
			ArrayList<String> organisationTags = makeCommonHelpers.getFilteredUserTags( email , ORGANISATION_FILTER , SUFIXES );

			NodeRef organisationsContainer = null;
			Serializable[] keys = new Serializable[] { DEFAULT_ATTRIBUTE };
			JSONArray defaults = makeCommonHelpers.getAttribute( keys );
			for( Object orgDef : defaults ){
				JSONObject entry = (JSONObject) orgDef;
				if( ( (String) entry.get( PROPERTY_KEY ) ).equals( DEFAULT_ORGANISATIONS_ATTRIBUTE ) ) {
					String organisationsContainerNodeRef = (String) entry.get( CONTAINER_KEY );
					organisationsContainer = new NodeRef( organisationsContainerNodeRef );
					break;
				}
			}
			if( organisationsContainer == null ){
				String errorMessage = message.get( "error.noOrganisationsContainerFound" , null );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_INTERNAL_SERVER_ERROR ) ) );
			}
			for( String organisationTag : organisationTags ){
				String organisationName = organisationTag.replaceFirst( ORGANISATION_FILTER , "" );
				NodeRef organisationNode = nodeService.getChildByName( organisationsContainer , ContentModel.ASSOC_CONTAINS , organisationName );
				if( organisationNode != null ) organisationNodes.add( organisationNode );
			}
			logger.debug( "[" + RemoveAuthentication.class.getName() + "] Found organisation nodes: " + organisationNodes );

			boolean userAuthorized = makeCommonHelpers.userIsSectionAdmin( authenticatedUserName , USER_ADMIN_AUTHORITY ) || makeCommonHelpers.userIsOrganisationsAdmin( authenticatedUserName , organisationNodes , COORDINATOR_SUFIX );
			if( !userAuthorized ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( authenticatedUserName );
				String errorMessage = message.get( "error.unauthorized" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_FORBIDDEN ) ) );
			}

			NodeRef person = personService.getPerson( email );
			if( person == null ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.personDoesNotExist" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			personService.deletePerson( person , true );

			AuthenticationUtil.setRunAsUser( authenticatedUserName );

			model.put( "response", email );
			ArrayList<String> args = new ArrayList<String>(1);
			args.add( email );
			String parsedMessage = message.get( "success.text" , args );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + RemoveAuthentication.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + RemoveAuthentication.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + RemoveAuthentication.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + RemoveAuthentication.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + RemoveAuthentication.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , RemoveAuthentication.class );
			return null;
		}
		return model;
	}
}
