"""
Additions to MyTardis's REST API for the ImageTrove
uploader. A lot of the code here is directly adapted from
mytardis/tardis/tardis_portal/api.py
"""

import logging
import traceback
from django.conf import settings
import pwgen
import simplejson

from tastypie import fields
from tastypie.resources import Resource
from tastypie.constants import ALL_WITH_RELATIONS

import tardis.tardis_portal.api
from tardis.tardis_portal.models.experiment import Experiment
from tardis.tardis_portal.models.parameters import Schema
from tardis.tardis_portal.models.parameters import ParameterName
from tardis.tardis_portal.models.parameters import ExperimentParameter
from tardis.tardis_portal.models.parameters import ExperimentParameterSet
from tardis.tardis_portal.models.datafile import DataFile, DataFileObject
from tardis.tardis_portal.models.parameters import DatafileParameter
from tardis.tardis_portal.models.parameters import DatafileParameterSet

from django.contrib.auth.models import User
from django.contrib.auth.models import Group, Permission

from tardis.tardis_portal.models import ObjectACL
from tardis.tardis_portal.models import UserProfile

from tardis.tardis_portal.auth.localdb_auth import django_user

logger = logging.getLogger(__name__)

default_authentication = tardis.tardis_portal.api.MyTardisAuthentication()

if settings.DEBUG:
    default_serializer = tardis.tardis_portal.api.PrettyJSONSerializer()
else:
    default_serializer = tardis.tardis_portal.api.Serializer()

def _get_value(eps, name):
    """
    Find the first matching value in an experiment parameterset.
    """

    for p in eps.parameters:
        str(p) # force calculation of _name_cache
        if p._name_cache.name == name:
            return p.string_value

    return None

def _get_group(name):
    if Group.objects.filter(name=name).count() == 0:
        g = Group(name=name)
        g.save()
    else:
        g = Group.objects.get(name=name)

    return g

def _get_user(email):
    if User.objects.filter(username__iexact=email).count() > 0:
        u = User.objects.get(username__iexact=email)
    else:
        u = User.objects.create_user(
                            email,
                            email,
                            pwgen.pwgen(25),
                            first_name='',
                            last_name='',
                            )
        UserProfile(user=u).save()

    return u

class ReplicaAppResource(tardis.tardis_portal.api.ReplicaResource):
    def __init__(self, *args, **kwargs):
        self.as_super = super(ReplicaAppResource, self)
        self.as_super.__init__(*args, **kwargs)

    class Meta(tardis.tardis_portal.api.MyTardisModelResource.Meta):
        queryset = DataFileObject.objects.all()
        filtering = {
            'verified': ('exact',),
            'url': ('exact', 'startswith'),
        }
        resource_name = 'replica'

    def hydrate(self, bundle):
        bundle = self.as_super.hydrate(bundle)

        if 'url' in bundle.data:
            bundle.data['uri'] = bundle.data['url']
        return bundle

# add name_cache field
class ExperimentParameterAppResource(tardis.tardis_portal.api.ParameterResource):
    parameterset = fields.ForeignKey('tardis.apps.imagetrove.api.ExperimentParameterSetAppResource',
                                     'parameterset')

    class Meta(tardis.tardis_portal.api.ParameterResource.Meta):
        queryset = tardis.tardis_portal.api.ExperimentParameter.objects.all()
        resource_name = 'experimentparameter' # mapped to imagetrove_experimentparameter by MyTARDIS' urls.py

    # Add the name_cache field:
    def dehydrate(self, bundle):
        try:
            str(bundle.obj) # force computation of _name_cache.
            bundle.data['name_cache'] = bundle.obj._name_cache.name
        except AttributeError:
            bundle.data['name_cache'] = ''

        return bundle

"""

Note on the weird as_super stuff in some of the __init__ methods:

Django was exploding (somewhat nondeterministically) with the error

    TypeError: super(type, obj): obj must be an instance or subtype of type

due to the line

    super(tardis.tardis_portal.api.ExperimentParameterSetResource, self).save_m2m(bundle)

but in this case 'self' was *definitely* an instance of
'ExperimentParameterSetResource'.

For an explanation, see
https://thingspython.wordpress.com/2010/09/27/another-super-wrinkle-raising-typeerror/
in particular this quote:

    Completely outside of the product, I created a little module,
    a.py, containing an empty class A. Then from the Python prompt,
    I ran these commands:

    >>> import imp
    >>> m = imp.find_module("a")
    >>> a = imp.load_module("a", *m)
    >>> a.A
    <class 'a.A'>
    >>> aobj = a.A()
    >>> aobj.__class__
    <class 'a.A'>

    Now that I had an object created, I reloaded the a module:

    >>> a = imp.load_module("a", *m)
    >>> print a.A
    <class 'a.A'>
    >>> isinstance(aobj, a.A)
    False

    I had recreated my "impossible" condition, an instance of
    a.A that fails isinstance(aobj, a.A).

    The final proof, calling super() as in the original bug:

    >>> super(a.A, aobj)
    Traceback (most recent call last):
    File "<stdin>", line 1, in
    TypeError: super(type, obj): obj must be an instance or subtype of type

The author provides the as_super workaround, which does save us here.

"""


class ExperimentParameterSetAppResource(tardis.tardis_portal.api.ParameterSetResource):
    def __init__(self, *args, **kwargs):
        self.as_super = super(ExperimentParameterSetAppResource, self)
        self.as_super.__init__(*args, **kwargs)

    experiment = fields.ForeignKey(
        'tardis.apps.imagetrove.api.ExperimentAppResource', 'experiment')
    parameters = fields.ToManyField(
        'tardis.apps.imagetrove.api.ExperimentParameterAppResource',
        'experimentparameter_set',
        related_name='parameterset', full=True, null=True)

    def save_m2m(self, bundle):
        # super(tardis.tardis_portal.api.ExperimentParameterSetResource, self).save_m2m(bundle)
        self.as_super.save_m2m(bundle)

    class Meta(tardis.tardis_portal.api.ParameterSetResource.Meta):
        queryset = ExperimentParameterSet.objects.all()
        resource_name = 'experimentparameterset'

class ObjectACLAppResource(tardis.tardis_portal.api.ModelResource):
    class Meta:
        queryset = ObjectACL.objects.all()
        authentication = default_authentication
        authorization = tardis.tardis_portal.api.ACLAuthorization()
        resource_name = 'objectacl'

    def dehydrate(self, bundle):
        """
        For convenience, add a related_group attribute that has the full
        details of the Group that this ObjectACL refers to (found using get_related_object_group()).
        """

        rog = bundle.obj.get_related_object_group()
        if rog is not None:
            # http://stackoverflow.com/questions/13565975/convert-a-queryset-to-json-using-tastypie-resource
            group_resource = tardis.tardis_portal.api.GroupResource()
            rog_bundle = group_resource.build_bundle(obj=rog, request=bundle.request)
            bundle.data['related_group'] = tardis.tardis_portal.api.GroupResource.full_dehydrate(group_resource, rog_bundle)
        else:
            bundle.data['related_group'] = None

        return bundle

    def hydrate(self, bundle):
        # Fill in the content type.
        if bundle.data['content_type'] == 'experiment':
            experiment = tardis.tardis_portal.api.Experiment.objects.get(pk=bundle.data['object_id'])
            bundle.obj.content_type = experiment.get_ct()
        else:
            raise NotImplementedError(str(bundle.obj))
        return bundle

class ExperimentAppResource(tardis.tardis_portal.api.MyTardisModelResource):
    created_by = fields.ForeignKey(tardis.tardis_portal.api.UserResource, 'created_by')
    parameter_sets = fields.ToManyField(
        'tardis.apps.imagetrove.api.ExperimentParameterSetAppResource',
        'experimentparameterset_set',
        related_name='experiment',
        full=True, null=True)
    objectacls = fields.ToManyField(
                    'tardis.apps.imagetrove.api.ObjectACLAppResource',
                    'objectacls',
                    related_name='objectacls',
                    full=True, null=True)

    def __init__(self, *args, **kwargs):
        self.as_super = super(ExperimentAppResource, self)
        self.as_super.__init__(*args, **kwargs)

    class Meta(tardis.tardis_portal.api.MyTardisModelResource.Meta):
        queryset = Experiment.objects.all()
        filtering = {
            'id': ('exact', ),
            'title': ('exact',),
        }
        always_return_data = True
        resource_name = 'experiment'

    def dehydrate(self, bundle):
        exp = bundle.obj
        authors = [{'name': a.author, 'url': a.url}
                   for a in exp.experimentauthor_set.all()]
        bundle.data['authors'] = authors
        lic = exp.license
        if lic is not None:
            bundle.data['license'] = {
                'name': lic.name,
                'url': lic.url,
                'description': lic.internal_description,
                'image_url': lic.image_url,
                'allows_distribution': lic.allows_distribution,
            }
        owners = exp.get_owners()
        bundle.data['owner_ids'] = [o.id for o in owners]
        return bundle

    def hydrate_m2m(self, bundle):
        '''
        create ACL before any related objects are created in order to use
        ACL permissions for those objects.
        '''
        if getattr(bundle.obj, 'id', False):
            experiment = bundle.obj
            # TODO: unify this with the view function's ACL creation,
            # maybe through an ACL toolbox.
            acl = ObjectACL(content_type=experiment.get_ct(),
                            object_id=experiment.id,
                            pluginId=django_user,
                            entityId=str(bundle.request.user.id),
                            canRead=True,
                            canWrite=True,
                            canDelete=True,
                            isOwner=True,
                            aclOwnershipType=ObjectACL.OWNER_OWNED)
            acl.save()

        # return super(tardis.tardis_portal.api.ExperimentResource, self).hydrate_m2m(bundle)
        return self.as_super.hydrate_m2m(bundle)

    def obj_create(self, bundle, **kwargs):
        '''experiments need at least one ACL to be available through the
        ExperimentManager (Experiment.safe)
        Currently not tested for failed db transactions as sqlite does not
        enforce limits.
        '''
        user = bundle.request.user
        bundle.data['created_by'] = user
        # bundle = super(tardis.tardis_portal.api.ExperimentResource, self).obj_create(bundle, **kwargs)
        bundle = self.as_super.obj_create(bundle, **kwargs)
        return bundle

class DatasetParameterAppResource(tardis.tardis_portal.api.ParameterResource):
    parameterset = fields.ForeignKey(tardis.tardis_portal.api.DatasetParameterSetResource,
                                     'parameterset')

    class Meta(tardis.tardis_portal.api.ParameterResource.Meta):
        queryset = tardis.tardis_portal.api.DatasetParameter.objects.all()
        resource_name = 'datasetparameter'

    def dehydrate(self, bundle):
        try:
            str(bundle.obj) # force computation of _name_cache.
            bundle.data['name_cache'] = bundle.obj._name_cache.name
        except AttributeError:
            bundle.data['name_cache'] = ''

        return bundle

class DatasetParameterSetAppResource(tardis.tardis_portal.api.ParameterSetResource):
    dataset = fields.ForeignKey(
        'tardis.apps.imagetrove.api.DatasetAppResource', 'dataset')
    parameters = fields.ToManyField(
        'tardis.apps.imagetrove.api.DatasetParameterAppResource',
        'datasetparameter_set',
        related_name='parameterset', full=True, null=True)

    class Meta(tardis.tardis_portal.api.ParameterSetResource.Meta):
        queryset = tardis.tardis_portal.api.DatasetParameterSet.objects.all()
        resource_name = 'datasetparameterset'

class DatasetAppResource(tardis.tardis_portal.api.DatasetResource):
    experiments = fields.ToManyField(
                            ExperimentAppResource, 'experiments', related_name='datasets')
    parameter_sets = fields.ToManyField(
                            'tardis.apps.imagetrove.api.DatasetParameterSetAppResource',
                            'datasetparameterset_set',
                            related_name='dataset',
                            full=True, null=True)

    class Meta(tardis.tardis_portal.api.MyTardisModelResource.Meta):
        queryset = tardis.tardis_portal.api.Dataset.objects.all()
        filtering = {
            'id': ('exact', ),
            'experiments': tardis.tardis_portal.api.ALL_WITH_RELATIONS,
            'description': ('exact', ),
            'directory': ('exact', ),
        }
        always_return_data = True

        resource_name = 'imagetrove_dataset'

    # Identical to parent's definition except for DataFileAppResource
    # on a single line of code.
    def get_datafiles(self, request, **kwargs):
        file_path = kwargs.get('file_path', None)
        dataset_id = kwargs['pk']

        datafiles = DataFile.objects.filter(dataset__id=dataset_id)
        auth_bundle = self.build_bundle(request=request)
        auth_bundle.obj = DataFile()
        self.authorized_read_list(
            datafiles, auth_bundle
            )
        del kwargs['pk']
        del kwargs['file_path']
        kwargs['dataset__id'] = dataset_id
        if file_path is not None:
            kwargs['directory__startswith'] = file_path
        df_res = DataFileAppResource() # <--- only difference
        return df_res.dispatch('list', request, **kwargs)

class DataFileAppResource(tardis.tardis_portal.api.MyTardisModelResource):
    dataset = fields.ForeignKey(tardis.tardis_portal.api.DatasetResource, 'dataset')
    parameter_sets = fields.ToManyField(
        'tardis.apps.imagetrove.api.DatafileParameterSetAppResource',
        'datafileparameterset_set',
        related_name='datafile',
        full=True, null=True)
    datafile = fields.FileField()
    replicas = fields.ToManyField(
        'tardis.tardis_portal.api.ReplicaResource',
        'file_objects',
        related_name='datafile', full=True, null=True)
    temp_url = None

    class Meta(tardis.tardis_portal.api.MyTardisModelResource.Meta):
        queryset = DataFile.objects.all()
        filtering = {
            'directory': ('exact', 'startswith'),
            'dataset': ALL_WITH_RELATIONS,
            'filename': ('exact', ),
        }
        resource_name = 'dataset_file'

class DatafileParameterSetAppResource(tardis.tardis_portal.api.ParameterSetResource):
    dataset_file = fields.ForeignKey(
        'tardis.apps.imagetrove.api.DataFileAppResource', 'datafile')
    parameters = fields.ToManyField(
        'tardis.apps.imagetrove.api.DatafileParameterAppResource',
        'datafileparameter_set',
        related_name='parameterset', full=True, null=True)

    class Meta(tardis.tardis_portal.api.ParameterSetResource.Meta):
        queryset = tardis.tardis_portal.api.DatafileParameterSet.objects.all()
        resource_name = 'datafile'

class DatafileParameterAppResource(tardis.tardis_portal.api.ParameterResource):
    parameterset = fields.ForeignKey('tardis.apps.imagetrove.api.DatafileParameterSetAppResource',
                                     'parameterset')

    class Meta(tardis.tardis_portal.api.ParameterResource.Meta):
        queryset = DatafileParameter.objects.all()

    # Add the name_cache field:
    def dehydrate(self, bundle):
        try:
            str(bundle.obj) # force computation of _name_cache.
            bundle.data['name_cache'] = bundle.obj._name_cache.name
        except AttributeError:
            bundle.data['name_cache'] = ''

        return bundle

class UserAppResource(tardis.tardis_portal.api.ModelResource):
    class Meta:
        authentication = default_authentication
        authorization = tardis.tardis_portal.api.ACLAuthorization()
        queryset = tardis.tardis_portal.api.User.objects.all()
        # allowed_methods = ['get', 'put']
        fields = ['username', 'first_name', 'last_name', 'email', 'groups', 'is_superuser']
        serializer = default_serializer

        resource_name = 'user'

    groups = fields.ToManyField(
        'tardis.tardis_portal.api.GroupResource',
        'groups',
        related_name='groups', full=True, null=True)

    def obj_create(self, bundle, **kwargs):
        # Does someone already exist with this email address? We use AAF for auth...
        if User.objects.filter(email__iexact=bundle.data['username']).count() > 0:
            bundle.obj = User.objects.get(email__iexact=bundle.data['username'])
        else:
            if bundle.data['is_superuser']:
                u = User.objects.create_superuser(
                                    bundle.data['username'],
                                    bundle.data['username'],
                                    pwgen.pwgen(25),
                                    first_name=bundle.data['first_name'],
                                    last_name=bundle.data['last_name'],
                                    )
            else:
                u = User.objects.create_user(
                                    bundle.data['username'],
                                    bundle.data['username'],
                                    pwgen.pwgen(25),
                                    first_name=bundle.data['first_name'],
                                    last_name=bundle.data['last_name'],
                                    )
            UserProfile(user=u).save()

            bundle.obj = u

        for group in bundle.data['groups']:
            bundle.obj.groups.add(Group.objects.get(pk=group['id']))
            bundle.obj.save()

        return bundle

    def obj_update(self, bundle, **kwargs):
        # http://django-tastypie.readthedocs.org/en/latest/non_orm_data_sources.html
        # http://stackoverflow.com/questions/11225110/obj-create-not-working-in-tastypie

        user = User.objects.get(username=bundle.data['username'])
        for group in bundle.data['groups']:
            user.groups.add(Group.objects.get(pk=group['id']))
            user.save()

        return bundle

class PermissionAppResource(tardis.tardis_portal.api.ModelResource):
    class Meta:
        queryset = Permission.objects.all()
        authentication = default_authentication
        authorization = tardis.tardis_portal.api.ACLAuthorization()
        resource_name = 'permission'

class GroupAppResource(tardis.tardis_portal.api.ModelResource):
    class Meta:
        authentication = default_authentication
        authorization = tardis.tardis_portal.api.ACLAuthorization()
        queryset = tardis.tardis_portal.api.Group.objects.all()
        resource_name = 'group'

    permissions = fields.ToManyField(
                            'tardis.apps.imagetrove.api.PermissionAppResource',
                            'permissions',
                            related_name='permissions', full=True, null=True)

class UserProjectACLAppResource(Resource):
    class Meta:
        authentication = tardis.tardis_portal.api.default_authentication
        authorization  = tardis.tardis_portal.api.ACLAuthorization()
        resource_name = 'userprojectacl'

    def obj_get_list(self, bundle, **kwargs):
        return []

    def obj_create(self, bundle, **kwargs):
        acl_pairs = simplejson.loads(bundle.data['json_data'])['acl_pairs']
        acl_pairs = [(u.lower(), p) for (u, p) in acl_pairs]

        # Users in supplied list:
        # users = dict(acl_pairs) # acl_pairs :: [(Email, ProjectId)]

        # Users currently in MyTardis apart from the special admin user:
        #current_users = [u.email.lower() for u in User.objects.all() if u.username != 'admin']

        #for u in current_users:
        #    if u not in users:
        #        User.objects.get(email__iexact=u).delete()

        for (email, project_id) in acl_pairs:
            project_name = 'Project ' + project_id

            # Create this group (for the project):
            g = _get_group(project_name)

            # Create this user:
            u = _get_user(email)

            # Add this user to the group:
            u.groups.add(g)
            u.save()

        # Apply ACLs for experiments.
        for eps in ExperimentParameterSet.objects.all():
            for p in eps.parameters:
                str(p) # force calculation of _name_cache
                if p._name_cache.name != 'Project': continue

                project_name = p.string_value

                g = _get_group(project_name)

                if ObjectACL.objects.filter(aclOwnershipType=1,
                                            canRead=True,
                                            entityId=str(g.id),
                                            object_id=eps.experiment.id).count() == 0:
                    oacl = ObjectACL(content_type=eps.experiment.get_ct(),
                                     aclOwnershipType=1,
                                     canRead=True,
                                     canWrite=False,
                                     canDelete=False,
                                     entityId=str(g.id),
                                     object_id=eps.experiment.id,
                                     isOwner=False,
                                     pluginId="django_group")
                    oacl.save()


        # Apply access for operators.
        for eps in ExperimentParameterSet.objects.all():
            operator_emails  = _get_value(eps, 'Operator')
            instrument       = _get_value(eps, 'Instrument')

            if instrument is not None:
                operator_group_name = 'OPERATOR :: ' + instrument
                operator_group = _get_group(operator_group_name)
            else:
                # FIXME log warning somewhere
                continue

            if operator_emails is not None:
                operator_emails = operator_emails.split() # multiple email addresses
            else:
                # FIXME log warning somewhere
                continue

            # For each operator, create/add them as a user, add them to the group,
            # and add the ObjectACL for this experiment.
            for operator_email in operator_emails:
                operator = _get_user(operator_email)
                operator.groups.add(operator_group)
                operator.save()

                if ObjectACL.objects.filter(aclOwnershipType=1,
                                            canRead=True,
                                            entityId=str(operator_group.id),
                                            object_id=eps.experiment.id).count() == 0:
                    oacl = ObjectACL(content_type=eps.experiment.get_ct(),
                                     aclOwnershipType=1,
                                     canRead=True,
                                     canWrite=False,
                                     canDelete=False,
                                     entityId=str(operator_group.id),
                                     object_id=eps.experiment.id,
                                     isOwner=False,
                                     pluginId="django_group")
                    oacl.save()

    def deserialize(self, request, data, format=None):
        if format == 'application/x-www-form-urlencoded':
            return request.POST
