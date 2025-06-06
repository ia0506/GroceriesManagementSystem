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
import java.util.List;
import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import usercommons.proxies.CustomEntity;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import com.mendix.systemwideinterfaces.core.meta.IMetaObject;

public class GetCustomEntityNames extends CustomJavaAction<java.util.List<IMendixObject>>
{
	public GetCustomEntityNames(IContext context)
	{
		super(context);
	}

	@java.lang.Override
	public java.util.List<IMendixObject> executeAction() throws Exception
	{
		// BEGIN USER CODE
		List<IMendixObject> list = new ArrayList<>();
		Iterable<IMetaObject> metaObjects = Core.getMetaObjects();
		for (IMetaObject metaObject : metaObjects) {
			if (inheritsFromSystemUser(metaObject)) {
				IMendixObject commonEntity = Core.instantiate(getContext(), CustomEntity.entityName);
				commonEntity.setValue(getContext(), CustomEntity.MemberNames.Name.name(), metaObject.getName());
				list.add(commonEntity);
			}
		}
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
		return "GetCustomEntityNames";
	}

	// BEGIN EXTRA CODE
	private boolean inheritsFromSystemUser(IMetaObject metaObject) {
		if ("System.User".equals(metaObject.getName())) {
	        return true;
	    }
		IMetaObject current = metaObject.getSuperObject();
		while (current != null) {
			if ("System.User".equals(current.getName())) {
				return true;
			}
			current = current.getSuperObject();
		}
		return false;
	}
	// END EXTRA CODE
}
