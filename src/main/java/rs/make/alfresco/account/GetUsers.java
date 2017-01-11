package rs.make.alfresco.account;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.alfresco.model.ContentModel;
import org.alfresco.query.PagingRequest;
import org.alfresco.query.PagingResults;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.MutableAuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.Pair;
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

public class GetUsers extends DeclarativeWebScript {

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

	protected NamespaceService namespaceService;
	public NamespaceService getNamespaceService() {
		return namespaceService;
	}
	public void setNamespaceService( NamespaceService namespaceService ) {
		this.namespaceService = namespaceService;
	}

	protected AuthorityService authorityService;
	public AuthorityService getAuthorityService() {
		return authorityService;
	}
	public void setAuthorityService( AuthorityService authorityService ) {
		this.authorityService = authorityService;
	}

	protected MutableAuthenticationService authenticationService;
	public MutableAuthenticationService getAuthenticationService() {
		return authenticationService;
	}
	public void setAuthenticationService( MutableAuthenticationService authenticationService ) {
		this.authenticationService = authenticationService;
	}

	private final String PERSON_ASPECT_MODEL = "http://www.wbif.eu/model/document/1.0";
	private final String PERSON_ASPECT_NAME = "person";
	private final QName PERSON_ASPECT = QName.createQName( PERSON_ASPECT_MODEL , PERSON_ASPECT_NAME );
	private final String PERSON_ASPECT_ORGANISATION_NAME = "organisation";
	private final QName PERSON_ASPECT_ORGANISATION = QName.createQName( PERSON_ASPECT_MODEL , PERSON_ASPECT_ORGANISATION_NAME );
	private final String AUTHORITIES_NAME = "authorities";
	private final QName AUTHORITIES = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , AUTHORITIES_NAME );
	private final String ACTIVE_NAME = "active";
	private final QName ACTIVE = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , ACTIVE_NAME );

	private final String AUTHORITY_NAME = "authority-name";
	private final String AUTHORITY_DISPLAY_NAME = "authority-display-name";

	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;

	private final int DEFAULT_SKIP = 0;
	private final int DEFAULT_LIMIT = 20;

	private final String SKIP_KEY = "skip";
	private final String LIMIT_KEY = "limit";
	private final String TOTAL_KEY_LOWER = "total-lower";
	private final String TOTAL_KEY_UPPER = "total-upper";

	private final String REQUEST_TERM_KEY = "term";
	private final String REQUEST_SORT_BY_KEY = "sort-by";
	private final String REQUEST_SORT_DIR_KEY = "sort-dir";

	private static Logger logger = Logger.getLogger( GetUsers.class );

	@SuppressWarnings("unchecked")
	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			String authenticatedUserName = AuthenticationUtil.getFullyAuthenticatedUser();
			if( authenticatedUserName == null ){
				authenticatedUserName = AuthenticationUtil.getGuestUserName();
				AuthenticationUtil.setRunAsUser( authenticatedUserName );
			}

			String term = makeCommonHelpers.getString( req , REQUEST_TERM_KEY , message , status , false );
			String sortBy = makeCommonHelpers.getString( req , REQUEST_SORT_BY_KEY , message , status , false );
			Boolean sortDir = makeCommonHelpers.getBooleanObj( req , REQUEST_SORT_DIR_KEY , message , status , false );
			int skip = makeCommonHelpers.getSkip( req , message , status , DEFAULT_SKIP );
			int limit = makeCommonHelpers.getLimit( req , message , status , DEFAULT_LIMIT );

//			if( term == null ) term = "";

			List<QName> lookInProperties = new ArrayList<QName>();
//			3 sort/filter properties are max allowed by API ?!!!
			lookInProperties.add( ContentModel.PROP_USERNAME );
			lookInProperties.add( ContentModel.PROP_FIRSTNAME );
			lookInProperties.add( PERSON_ASPECT_ORGANISATION );

			Set<QName> inclusiveAspects = new HashSet<QName>();
			inclusiveAspects.add( PERSON_ASPECT );

			List<Pair<QName, Boolean>> sortProps = new ArrayList<Pair<QName, Boolean>>();
			QName sortField = ContentModel.PROP_FIRSTNAME;
			if( sortBy != null ){
				try{
					sortField = ( sortBy.startsWith( "{" ) ) ? QName.createQName( sortBy ) : QName.createQName( sortBy , namespaceService );
				}
				catch( Exception e ){
					logger.error( "[" + GetUsers.class.getName() + "] Exception when trying to resolve provided sort field QName: \"" + e.getMessage() + "\"." );
				}
			}
			if( sortDir == null ) sortDir = new Boolean( true );
			Pair<QName, Boolean> sortProp = new Pair<QName, Boolean>( sortField , sortDir );
			sortProps.add( sortProp );

			PagingRequest pagingRequest = new PagingRequest( skip , limit );
			pagingRequest.setRequestTotalCountMax( Integer.MAX_VALUE );

			PagingResults<PersonService.PersonInfo> users = personService.getPeople( term , lookInProperties , inclusiveAspects , null , false , sortProps , pagingRequest );
			Pair<Integer, Integer> count = users.getTotalResultCount();
			List<PersonService.PersonInfo> page = users.getPage();
			JSONArray response = new JSONArray();

			AuthenticationUtil.setRunAsUserSystem();

			for( PersonService.PersonInfo user : page ){
				String userName = user.getUserName();
				Map<QName, Serializable> properties = nodeService.getProperties( user.getNodeRef() );
				JSONArray authorities = new JSONArray();
				Set<String> auths = authorityService.getAuthoritiesForUser( userName );
				for( String authName : auths ){
					JSONObject authObj = new JSONObject();
					authObj.put( AUTHORITY_NAME , authName );
					authObj.put( AUTHORITY_DISPLAY_NAME , authorityService.getAuthorityDisplayName( authName ) );
					authorities.add( authObj );
				}
				properties.put( AUTHORITIES , authorities );

				boolean active = authenticationService.getAuthenticationEnabled( userName );
				properties.put( ACTIVE , active );

				response.add( properties );
			}

			AuthenticationUtil.setRunAsUser( authenticatedUserName );

			Map<String, Integer> counter = new HashMap<String, Integer>();
			counter.put( SKIP_KEY , skip );
			counter.put( LIMIT_KEY , limit );
			counter.put( TOTAL_KEY_LOWER , count.getFirst() );
			counter.put( TOTAL_KEY_UPPER , count.getSecond() );

			Gson gson = new Gson();
			model.put( "count", gson.toJson( counter ) );
			model.put( "response", gson.toJson( response ) );
			String parsedMessage = message.get( "success.text" , null );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + GetUsers.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + GetUsers.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + GetUsers.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + GetUsers.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + GetUsers.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , GetUsers.class );
			return null;
		}
		return model;
	}
}
