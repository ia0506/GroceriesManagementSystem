// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package usercommons.actions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import usercommons.proxies.CustomEntityMember;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import com.mendix.systemwideinterfaces.core.meta.IMetaObject;
import com.mendix.systemwideinterfaces.core.meta.IMetaPrimitive;

public class GetCustomEntityMemberNames extends CustomJavaAction<java.util.List<IMendixObject>>
{
	private final java.lang.String EntityName;

	public GetCustomEntityMemberNames(
		IContext context,
		java.lang.String _entityName
	)
	{
		super(context);
		this.EntityName = _entityName;
	}

	@java.lang.Override
	public java.util.List<IMendixObject> executeAction() throws Exception
	{
		// BEGIN USER CODE
		List<IMendixObject> list = new ArrayList<>();
		IMetaObject metaObject = Core.getMetaObject(this.EntityName);
		Collection<IMetaPrimitive> fields = (Collection<IMetaPrimitive>) metaObject.getMetaPrimitives();
		fields.forEach(field -> {
			IMendixObject customUserEntityMember = Core.instantiate(getContext(), CustomEntityMember.entityName);
			customUserEntityMember.setValue(getContext(), CustomEntityMember.MemberNames.Name.name(), field.getName());
			list.add(customUserEntityMember);
		});
		return list;
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "GetCustomEntityMemberNames";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
