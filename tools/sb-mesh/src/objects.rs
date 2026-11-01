use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

pub const OBJECT_MODEL_SCHEMA_VERSION: u16 = 1;
const MAX_ID_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MeshObjectId(String);

impl MeshObjectId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_stable_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MeshObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectVersionId(String);

impl ObjectVersionId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_stable_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectVersionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrincipalKind {
    User,
    Device,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId {
    pub kind: PrincipalKind,
    pub id: String,
}

impl Serialize for PrincipalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", self.kind.as_str(), self.id))
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let (kind, id) = value
            .split_once(':')
            .ok_or_else(|| serde::de::Error::custom("principal ID must use <kind>:<id>"))?;
        let kind = PrincipalKind::parse(kind)
            .ok_or_else(|| serde::de::Error::custom("unknown principal kind"))?;
        PrincipalId::new(kind, id).map_err(serde::de::Error::custom)
    }
}

impl PrincipalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::Group => "group",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "device" => Some(Self::Device),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

impl PrincipalId {
    pub fn new(kind: PrincipalKind, id: impl Into<String>) -> Result<Self, String> {
        let id = id.into();
        validate_stable_id(&id)?;
        Ok(Self { kind, id })
    }

    pub fn user(id: impl Into<String>) -> Result<Self, String> {
        Self::new(PrincipalKind::User, id)
    }

    pub fn device(id: impl Into<String>) -> Result<Self, String> {
        Self::new(PrincipalKind::Device, id)
    }

    pub fn group(id: impl Into<String>) -> Result<Self, String> {
        Self::new(PrincipalKind::Group, id)
    }
}

fn validate_stable_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_ID_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!(
            "Invalid stable ID '{value}'; use 1-{MAX_ID_LENGTH} ASCII letters, digits, '-', '_', '.', or ':'"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryPrincipal {
    User {
        display_name: String,
        enabled: bool,
    },
    Device {
        display_name: String,
        public_key: String,
        bound_user: Option<PrincipalId>,
        enabled: bool,
    },
    Group {
        display_name: String,
        members: BTreeSet<PrincipalId>,
        enabled: bool,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshDirectory {
    principals: BTreeMap<PrincipalId, DirectoryPrincipal>,
}

impl MeshDirectory {
    pub fn principals(&self) -> &BTreeMap<PrincipalId, DirectoryPrincipal> {
        &self.principals
    }

    pub fn add_user(&mut self, id: PrincipalId, display_name: String) -> Result<(), String> {
        self.insert_principal(
            id,
            PrincipalKind::User,
            DirectoryPrincipal::User {
                display_name,
                enabled: true,
            },
        )
    }

    pub fn add_device(
        &mut self,
        id: PrincipalId,
        display_name: String,
        public_key: String,
        bound_user: Option<PrincipalId>,
    ) -> Result<(), String> {
        if id.kind != PrincipalKind::Device {
            return Err("Device records require a device principal ID".to_string());
        }
        if public_key.trim().is_empty()
            || self.principals.values().any(|principal| {
                matches!(
                    principal,
                    DirectoryPrincipal::Device {
                        public_key: existing,
                        ..
                    } if existing == &public_key
                )
            })
        {
            return Err("Device public keys must be non-empty and unique".to_string());
        }
        if let Some(user_id) = &bound_user {
            if user_id.kind != PrincipalKind::User
                || !matches!(
                    self.principals.get(user_id),
                    Some(DirectoryPrincipal::User { .. })
                )
            {
                return Err("A device may only be bound to an existing user principal".to_string());
            }
        }
        self.insert_principal(
            id,
            PrincipalKind::Device,
            DirectoryPrincipal::Device {
                display_name,
                public_key,
                bound_user,
                enabled: true,
            },
        )
    }

    pub fn add_group(&mut self, id: PrincipalId, display_name: String) -> Result<(), String> {
        self.insert_principal(
            id,
            PrincipalKind::Group,
            DirectoryPrincipal::Group {
                display_name,
                members: BTreeSet::new(),
                enabled: true,
            },
        )
    }

    pub fn add_group_member(
        &mut self,
        group_id: &PrincipalId,
        member_id: PrincipalId,
    ) -> Result<(), String> {
        if group_id.kind != PrincipalKind::Group {
            return Err("Group membership target must be a group principal".to_string());
        }
        if !self.principals.contains_key(&member_id) {
            return Err(format!("Unknown group member principal: {:?}", member_id));
        }
        let Some(DirectoryPrincipal::Group { members, .. }) = self.principals.get_mut(group_id)
        else {
            return Err(format!("Unknown group principal: {:?}", group_id));
        };
        let rollback_member = member_id.clone();
        members.insert(member_id);

        if let Err(error) = self.validate_group_graph() {
            if let Some(DirectoryPrincipal::Group { members, .. }) =
                self.principals.get_mut(group_id)
            {
                members.remove(&rollback_member);
            }
            return Err(error.message);
        }
        Ok(())
    }

    pub fn set_enabled(&mut self, principal_id: &PrincipalId, enabled: bool) -> Result<(), String> {
        let principal = self
            .principals
            .get_mut(principal_id)
            .ok_or_else(|| format!("Unknown principal: {:?}", principal_id))?;
        match principal {
            DirectoryPrincipal::User {
                enabled: principal_enabled,
                ..
            }
            | DirectoryPrincipal::Device {
                enabled: principal_enabled,
                ..
            }
            | DirectoryPrincipal::Group {
                enabled: principal_enabled,
                ..
            } => *principal_enabled = enabled,
        }
        Ok(())
    }

    fn insert_principal(
        &mut self,
        id: PrincipalId,
        expected_kind: PrincipalKind,
        principal: DirectoryPrincipal,
    ) -> Result<(), String> {
        if id.kind != expected_kind {
            return Err(format!(
                "Principal kind mismatch: expected {expected_kind:?}, got {:?}",
                id.kind
            ));
        }
        if self.principals.contains_key(&id) {
            return Err(format!("Principal already exists: {id:?}"));
        }
        self.principals.insert(id, principal);
        Ok(())
    }

    fn validate_group_graph(&self) -> Result<(), GroupGraphError> {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        for id in self
            .principals
            .keys()
            .filter(|id| id.kind == PrincipalKind::Group)
        {
            let mut pending = vec![(id.clone(), false)];
            while let Some((current, exiting)) = pending.pop() {
                if exiting {
                    visiting.remove(&current);
                    visited.insert(current);
                    continue;
                }
                if visited.contains(&current) {
                    continue;
                }
                if !visiting.insert(current.clone()) {
                    return Err(GroupGraphError {
                        message: format!("Nested group cycle detected at {current:?}"),
                    });
                }
                pending.push((current.clone(), true));
                if let Some(DirectoryPrincipal::Group { members, .. }) =
                    self.principals.get(&current)
                {
                    pending.extend(
                        members
                            .iter()
                            .rev()
                            .filter(|member| member.kind == PrincipalKind::Group)
                            .cloned()
                            .map(|member| (member, false)),
                    );
                }
            }
        }
        Ok(())
    }

    fn effective_principals(
        &self,
        asserted_principals: &[PrincipalId],
    ) -> Result<BTreeSet<PrincipalId>, String> {
        let mut effective = BTreeSet::new();
        let mut expanded = BTreeSet::new();
        self.validate()?;
        let mut parent_groups: BTreeMap<PrincipalId, Vec<PrincipalId>> = BTreeMap::new();
        for (group_id, principal) in &self.principals {
            if let DirectoryPrincipal::Group {
                enabled: true,
                members,
                ..
            } = principal
            {
                for member in members {
                    parent_groups
                        .entry(member.clone())
                        .or_default()
                        .push(group_id.clone());
                }
            }
        }
        let mut pending = asserted_principals.to_vec();
        while let Some(id) = pending.pop() {
            let principal = self
                .principals
                .get(&id)
                .ok_or_else(|| format!("Unknown asserted principal: {id:?}"))?;
            let enabled = match principal {
                DirectoryPrincipal::User { enabled, .. }
                | DirectoryPrincipal::Device { enabled, .. }
                | DirectoryPrincipal::Group { enabled, .. } => *enabled,
            };
            if !enabled {
                return Err(format!("Disabled asserted principal or group: {id:?}"));
            }
            effective.insert(id.clone());
            if !expanded.insert(id.clone()) {
                continue;
            }
            if let DirectoryPrincipal::Group { members, .. } = principal {
                pending.extend(members.iter().cloned());
            }
            if let Some(groups) = parent_groups.get(&id) {
                pending.extend(groups.iter().cloned());
            }
        }
        Ok(effective)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut device_public_keys = BTreeSet::new();
        for (id, principal) in &self.principals {
            validate_stable_id(&id.id)?;
            let valid_kind = matches!(
                (id.kind, principal),
                (PrincipalKind::User, DirectoryPrincipal::User { .. })
                    | (PrincipalKind::Device, DirectoryPrincipal::Device { .. })
                    | (PrincipalKind::Group, DirectoryPrincipal::Group { .. })
            );
            if !valid_kind {
                return Err(format!("Directory principal kind mismatch for {id:?}"));
            }
            match principal {
                DirectoryPrincipal::Device {
                    public_key,
                    bound_user,
                    ..
                } => {
                    if public_key.trim().is_empty() || !device_public_keys.insert(public_key) {
                        return Err(format!(
                            "Device {id:?} has an empty or duplicated public key"
                        ));
                    }
                    if let Some(user_id) = bound_user {
                        if user_id.kind != PrincipalKind::User
                            || !matches!(
                                self.principals.get(user_id),
                                Some(DirectoryPrincipal::User { .. })
                            )
                        {
                            return Err(format!(
                                "Device {id:?} is bound to an unknown or non-user principal"
                            ));
                        }
                    }
                }
                DirectoryPrincipal::Group { members, .. } => {
                    for member in members {
                        if !self.principals.contains_key(member) {
                            return Err(format!(
                                "Group {id:?} references unknown principal {member:?}"
                            ));
                        }
                    }
                }
                DirectoryPrincipal::User { .. } => {}
            }
        }
        self.validate_group_graph().map_err(|error| error.message)
    }
}

struct GroupGraphError {
    message: String,
}

/// ACL-filtered, metadata-only view of an object for clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectSummary {
    pub id: MeshObjectId,
    pub display_name: String,
    pub parent_id: Option<MeshObjectId>,
    pub is_container: bool,
    pub readable: bool,
    pub version_id: Option<ObjectVersionId>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerKind {
    Folder,
    Share,
    Collection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshObjectKind {
    Container(ContainerKind),
    Blob { media_type: String },
    DatabaseRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObjectPermission {
    Discover,
    List,
    Read,
    ReadVersions,
    Create,
    Write,
    Append,
    Delete,
    Move,
    ManageAcl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectAce {
    pub principal: PrincipalId,
    pub effect: AclEffect,
    pub permissions: BTreeSet<ObjectPermission>,
    pub inherit_to_children: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectAcl {
    pub inherit_from_parent: bool,
    pub entries: Vec<ObjectAce>,
}

impl ObjectAcl {
    pub fn add_entry(
        &mut self,
        principal: PrincipalId,
        effect: AclEffect,
        permissions: impl IntoIterator<Item = ObjectPermission>,
        inherit_to_children: bool,
    ) {
        self.entries.push(ObjectAce {
            principal,
            effect,
            permissions: permissions.into_iter().collect(),
            inherit_to_children,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadReference {
    pub provider: String,
    pub locator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectVersion {
    pub id: ObjectVersionId,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub created_at: u64,
    pub created_by: PrincipalId,
    pub payload: PayloadReference,
}

impl ObjectVersion {
    pub fn from_content(
        id: ObjectVersionId,
        content: &[u8],
        created_at: u64,
        created_by: PrincipalId,
        payload: PayloadReference,
    ) -> Self {
        Self {
            id,
            content_hash: Sha256::digest(content).into(),
            size_bytes: content.len() as u64,
            created_at,
            created_by,
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshObject {
    pub id: MeshObjectId,
    pub kind: MeshObjectKind,
    pub display_name: String,
    pub parent_id: Option<MeshObjectId>,
    pub owner: PrincipalId,
    pub acl: ObjectAcl,
    pub versions: Vec<ObjectVersion>,
    pub current_version: Option<ObjectVersionId>,
}

impl MeshObject {
    pub fn new(
        id: MeshObjectId,
        kind: MeshObjectKind,
        display_name: String,
        parent_id: Option<MeshObjectId>,
        owner: PrincipalId,
    ) -> Self {
        Self {
            id,
            kind,
            display_name,
            parent_id,
            owner,
            acl: ObjectAcl {
                inherit_from_parent: true,
                entries: Vec::new(),
            },
            versions: Vec::new(),
            current_version: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AccessContext {
    mesh_id: String,
    device_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshObjectCatalog {
    pub schema_version: u16,
    pub mesh_id: String,
    pub directory: MeshDirectory,
    pub objects: BTreeMap<MeshObjectId, MeshObject>,
}

impl MeshObjectCatalog {
    pub fn new(mesh_id: impl Into<String>) -> Result<Self, String> {
        let mesh_id = mesh_id.into();
        validate_stable_id(&mesh_id)?;
        Ok(Self {
            schema_version: OBJECT_MODEL_SCHEMA_VERSION,
            mesh_id,
            directory: MeshDirectory::default(),
            objects: BTreeMap::new(),
        })
    }

    pub fn insert_object(&mut self, object: MeshObject) -> Result<(), String> {
        validate_stable_id(&object.id.0)?;
        if self.objects.contains_key(&object.id) {
            return Err(format!("Object already exists: {}", object.id));
        }
        if !self.directory.principals.contains_key(&object.owner) {
            return Err(format!("Unknown object owner: {:?}", object.owner));
        }
        self.validate_acl_principals(&object.acl)?;
        match &object.kind {
            MeshObjectKind::Container(_) => {
                if !object.versions.is_empty() || object.current_version.is_some() {
                    return Err("Container objects cannot have payload versions".to_string());
                }
            }

            MeshObjectKind::Blob { media_type } if media_type.trim().is_empty() => {
                return Err("Blob media type cannot be empty".to_string());
            }
            _ => {}
        }
        let mut version_ids = BTreeSet::new();
        for version in &object.versions {
            validate_stable_id(version.id.as_str())?;
            if !version_ids.insert(version.id.clone()) {
                return Err(format!("Duplicate object version: {}", version.id));
            }
            if !self.directory.principals.contains_key(&version.created_by) {
                return Err(format!("Unknown version creator: {:?}", version.created_by));
            }
            if version.payload.provider.trim().is_empty()
                || version.payload.locator.trim().is_empty()
            {
                return Err(format!(
                    "Version {} has an empty payload reference",
                    version.id
                ));
            }
        }
        if object.current_version.as_ref() != object.versions.last().map(|version| &version.id) {
            return Err("Object has an invalid current version reference".to_string());
        }
        if let Some(parent_id) = &object.parent_id {
            let parent = self
                .objects
                .get(parent_id)
                .ok_or_else(|| format!("Unknown parent object: {parent_id}"))?;
            if !matches!(parent.kind, MeshObjectKind::Container(_)) {
                return Err(format!("Parent object {parent_id} is not a container"));
            }
        }
        self.objects.insert(object.id.clone(), object);
        Ok(())
    }

    pub fn add_version(
        &mut self,
        object_id: &MeshObjectId,
        version: ObjectVersion,
    ) -> Result<(), String> {
        validate_stable_id(version.id.as_str())?;
        if version.payload.provider.trim().is_empty() || version.payload.locator.trim().is_empty() {
            return Err("Payload provider and locator cannot be empty".to_string());
        }
        if !self.directory.principals.contains_key(&version.created_by) {
            return Err(format!("Unknown version creator: {:?}", version.created_by));
        }
        let object = self
            .objects
            .get_mut(object_id)
            .ok_or_else(|| format!("Unknown object: {object_id}"))?;
        if matches!(object.kind, MeshObjectKind::Container(_)) {
            return Err("Container objects cannot have payload versions".to_string());
        }
        if object
            .versions
            .iter()
            .any(|existing| existing.id == version.id)
        {
            return Err(format!("Object version already exists: {}", version.id));
        }
        object.current_version = Some(version.id.clone());
        object.versions.push(version);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != OBJECT_MODEL_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported object catalog schema version {}",
                self.schema_version
            ));
        }
        validate_stable_id(&self.mesh_id)?;
        self.directory.validate()?;

        for (key, object) in &self.objects {
            validate_stable_id(key.as_str())?;
            if key != &object.id {
                return Err(format!(
                    "Object map key {key} does not match embedded ID {}",
                    object.id
                ));
            }
            if !self.directory.principals.contains_key(&object.owner) {
                return Err(format!("Unknown object owner: {:?}", object.owner));
            }
            self.validate_acl_principals(&object.acl)?;
            match &object.kind {
                MeshObjectKind::Container(_) => {
                    if !object.versions.is_empty() || object.current_version.is_some() {
                        return Err(format!(
                            "Container object {key} cannot have payload versions"
                        ));
                    }
                }
                MeshObjectKind::Blob { media_type } if media_type.trim().is_empty() => {
                    return Err(format!("Blob object {key} has an empty media type"));
                }
                _ => {}
            }

            let mut version_ids = BTreeSet::new();
            for version in &object.versions {
                validate_stable_id(version.id.as_str())?;
                if !version_ids.insert(version.id.clone()) {
                    return Err(format!("Duplicate version {} on object {key}", version.id));
                }
                if !self.directory.principals.contains_key(&version.created_by) {
                    return Err(format!(
                        "Unknown version creator on object {key}: {:?}",
                        version.created_by
                    ));
                }
                if version.payload.provider.trim().is_empty()
                    || version.payload.locator.trim().is_empty()
                {
                    return Err(format!(
                        "Version {} has an empty payload reference",
                        version.id
                    ));
                }
            }
            let latest_version = object.versions.last().map(|version| &version.id);
            if object.current_version.as_ref() != latest_version {
                return Err(format!(
                    "Object {key} has an invalid current version reference"
                ));
            }

            if let Some(parent_id) = &object.parent_id {
                let parent = self
                    .objects
                    .get(parent_id)
                    .ok_or_else(|| format!("Unknown parent object: {parent_id}"))?;
                if !matches!(parent.kind, MeshObjectKind::Container(_)) {
                    return Err(format!("Parent object {parent_id} is not a container"));
                }
            }
        }

        let mut visiting_objects = BTreeSet::new();
        let mut validated_objects = BTreeSet::new();
        for object in self.objects.values() {
            let mut pending = vec![(object.id.clone(), false)];
            while let Some((current_id, exiting)) = pending.pop() {
                if exiting {
                    visiting_objects.remove(&current_id);
                    validated_objects.insert(current_id);
                    continue;
                }
                if validated_objects.contains(&current_id) {
                    continue;
                }
                if !visiting_objects.insert(current_id.clone()) {
                    return Err(format!("Object hierarchy cycle detected at {current_id}"));
                }
                pending.push((current_id.clone(), true));
                if let Some(parent_id) = self
                    .objects
                    .get(&current_id)
                    .and_then(|current| current.parent_id.as_ref())
                {
                    pending.push((parent_id.clone(), false));
                }
            }
        }
        Ok(())
    }

    pub fn check_access(
        &self,
        object_id: &MeshObjectId,
        context: &AccessContext,
        required: &BTreeSet<ObjectPermission>,
    ) -> Result<bool, String> {
        if required.is_empty() {
            return Ok(false);
        }
        if context.mesh_id != self.mesh_id {
            return Err("Access context belongs to a different mesh".to_string());
        }
        let asserted_principals = self
            .directory
            .principals
            .iter()
            .find_map(|(id, principal)| match principal {
                DirectoryPrincipal::Device {
                    public_key,
                    enabled: true,
                    bound_user,
                    ..
                } if public_key == &context.device_public_key => {
                    let mut principals = vec![id.clone()];
                    if let Some(user_id) = bound_user {
                        principals.push(user_id.clone());
                    }
                    Some(Ok(principals))
                }
                DirectoryPrincipal::Device { public_key, .. }
                    if public_key == &context.device_public_key =>
                {
                    Some(Err("Authenticated device is disabled".to_string()))
                }
                _ => None,
            })
            .transpose()?
            .ok_or_else(|| "Authenticated device is not registered in this mesh".to_string())?;
        let effective = self.directory.effective_principals(&asserted_principals)?;
        let mut current_id = object_id.clone();
        let mut apply_parent_acl = false;
        let mut allowed = BTreeSet::new();
        let mut visited_objects = BTreeSet::new();

        loop {
            if !visited_objects.insert(current_id.clone()) {
                return Err(format!("Object hierarchy cycle detected at {current_id}"));
            }
            let object = self
                .objects
                .get(&current_id)
                .ok_or_else(|| format!("Unknown object: {current_id}"))?;
            self.validate_acl_principals(&object.acl)?;
            if current_id != *object_id && !apply_parent_acl {
                break;
            }
            for ace in &object.acl.entries {
                if (current_id == *object_id || ace.inherit_to_children)
                    && effective.contains(&ace.principal)
                {
                    let overlaps = ace
                        .permissions
                        .iter()
                        .any(|permission| required.contains(permission));
                    if ace.effect == AclEffect::Deny && overlaps {
                        return Ok(false);
                    }
                    if ace.effect == AclEffect::Allow {
                        allowed.extend(ace.permissions.iter().copied());
                    }
                }
            }
            if !object.acl.inherit_from_parent {
                break;
            }
            let Some(parent_id) = &object.parent_id else {
                break;
            };
            current_id = parent_id.clone();
            apply_parent_acl = true;
        }
        Ok(required.is_subset(&allowed))
    }

    pub fn check_access_for_authenticated_device_key(
        &self,
        object_id: &MeshObjectId,
        authenticated_public_key: &str,
        required: &BTreeSet<ObjectPermission>,
    ) -> Result<bool, String> {
        let context = self.access_context_for_authenticated_device(authenticated_public_key)?;
        self.check_access(object_id, &context, required)
    }

    /// Lists objects the authenticated device may discover, list or read, never including
    /// objects the ACL hides. Hidden objects are indistinguishable from nonexistent ones.
    // CVE-Threat: Information disclosure through object enumeration or ACL oracle.
    // Analysis: Names, hashes and sizes of unauthorized objects would leak mesh structure.
    // Hardening: Every entry is gated by an explicit ACL evaluation; any evaluation error
    // for a single object hides it (fail closed) and the result size is bounded.
    pub fn visible_summaries_for_authenticated_device(
        &self,
        authenticated_public_key: &str,
        limit: usize,
    ) -> Result<Vec<ObjectSummary>, String> {
        let context = self.access_context_for_authenticated_device(authenticated_public_key)?;
        let visibility = BTreeSet::from([
            ObjectPermission::Discover,
            ObjectPermission::List,
            ObjectPermission::Read,
        ]);
        let read = BTreeSet::from([ObjectPermission::Read]);
        let mut summaries = Vec::new();
        for (id, object) in &self.objects {
            if summaries.len() >= limit {
                break;
            }
            // check_access requires every permission in the set; probe each individually.
            let visible = visibility.iter().any(|permission| {
                self.check_access(id, &context, &BTreeSet::from([*permission]))
                    .unwrap_or(false)
            });
            if !visible {
                continue;
            }
            let readable = self.check_access(id, &context, &read).unwrap_or(false);
            let version = object.current_version.as_ref().and_then(|current| {
                object
                    .versions
                    .iter()
                    .find(|version| &version.id == current)
            });
            summaries.push(ObjectSummary {
                id: id.clone(),
                display_name: object.display_name.clone(),
                parent_id: object.parent_id.clone(),
                is_container: matches!(object.kind, MeshObjectKind::Container(_)),
                readable,
                version_id: version.filter(|_| readable).map(|v| v.id.clone()),
                size_bytes: version.filter(|_| readable).map(|v| v.size_bytes),
            });
        }
        Ok(summaries)
    }

    /// Create a non-serializable access context from a peer key already authenticated by the
    /// mesh transport. Callers must not pass a public key claimed in an unauthenticated request.
    pub(crate) fn access_context_for_authenticated_device(
        &self,
        authenticated_public_key: &str,
    ) -> Result<AccessContext, String> {
        if authenticated_public_key.trim().is_empty() {
            return Err("Authenticated device public key cannot be empty".to_string());
        }
        let matching_devices = self
            .directory
            .principals
            .values()
            .filter(|principal| {
                matches!(
                    principal,
                    DirectoryPrincipal::Device { public_key, .. }
                        if public_key == authenticated_public_key
                )
            })
            .count();
        if matching_devices != 1 {
            return Err(if matching_devices == 0 {
                "Authenticated device is not registered in this mesh".to_string()
            } else {
                "Authenticated device public key is ambiguous in this mesh".to_string()
            });
        }
        Ok(AccessContext {
            mesh_id: self.mesh_id.clone(),
            device_public_key: authenticated_public_key.to_string(),
        })
    }

    fn validate_acl_principals(&self, acl: &ObjectAcl) -> Result<(), String> {
        for ace in &acl.entries {
            if !self.directory.principals.contains_key(&ace.principal) {
                return Err(format!(
                    "ACL references unknown principal: {:?}",
                    ace.principal
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str) -> PrincipalId {
        PrincipalId::user(id).unwrap()
    }

    fn group(id: &str) -> PrincipalId {
        PrincipalId::group(id).unwrap()
    }

    fn object_id(id: &str) -> MeshObjectId {
        MeshObjectId::new(id).unwrap()
    }

    fn catalog_with_user() -> MeshObjectCatalog {
        let mut catalog = MeshObjectCatalog::new("engineering").unwrap();
        catalog
            .directory
            .add_user(user("alice"), "Alice".to_string())
            .unwrap();
        catalog
    }

    fn context_for_user(catalog: &mut MeshObjectCatalog, user_id: &PrincipalId) -> AccessContext {
        let device_id = PrincipalId::device(format!("device-{}", user_id.id)).unwrap();
        let public_key = format!("test-public-key-{}", user_id.id);
        catalog
            .directory
            .add_device(
                device_id,
                format!("{} device", user_id.id),
                public_key.clone(),
                Some(user_id.clone()),
            )
            .unwrap();
        catalog
            .access_context_for_authenticated_device(&public_key)
            .unwrap()
    }

    #[test]
    fn stable_ids_are_validated_and_typed() {
        assert!(MeshObjectId::new("object:0001").is_ok());
        assert!(MeshObjectId::new("../secret").is_err());
        assert!(ObjectVersionId::new("").is_err());
        assert_ne!(user("alice"), PrincipalId::device("alice").unwrap());
    }

    #[test]
    fn nested_groups_resolve_and_cycles_are_rejected_without_mutation() {
        let mut directory = MeshDirectory::default();
        let alice = user("alice");
        let developers = group("developers");
        let db_readers = group("db-readers");
        directory
            .add_user(alice.clone(), "Alice".to_string())
            .unwrap();
        directory
            .add_group(developers.clone(), "Developers".to_string())
            .unwrap();
        directory
            .add_group(db_readers.clone(), "DB Readers".to_string())
            .unwrap();
        directory
            .add_group_member(&developers, alice.clone())
            .unwrap();
        directory
            .add_group_member(&db_readers, developers.clone())
            .unwrap();

        let effective = directory
            .effective_principals(&[db_readers.clone()])
            .unwrap();
        assert!(effective.contains(&db_readers));
        assert!(effective.contains(&developers));
        assert!(effective.contains(&alice));

        assert!(directory.add_group_member(&developers, db_readers).is_err());
        let DirectoryPrincipal::Group { members, .. } =
            directory.principals().get(&developers).unwrap()
        else {
            panic!("expected developer group");
        };
        assert!(!members.contains(&group("db-readers")));
    }

    #[test]
    fn device_and_user_groups_remain_separate_principals() {
        let mut directory = MeshDirectory::default();
        let alice = user("alice");
        let laptop = PrincipalId::device("alice-laptop").unwrap();
        let device_group = group("managed-devices");
        directory
            .add_user(alice.clone(), "Alice".to_string())
            .unwrap();
        directory
            .add_device(
                laptop.clone(),
                "Alice laptop".to_string(),
                "public-key".to_string(),
                Some(alice.clone()),
            )
            .unwrap();
        directory
            .add_group(device_group.clone(), "Managed devices".to_string())
            .unwrap();
        directory
            .add_group_member(&device_group, laptop.clone())
            .unwrap();

        let user_context = directory.effective_principals(&[alice.clone()]).unwrap();
        assert!(!user_context.contains(&device_group));
        let combined_context = directory.effective_principals(&[alice, laptop]).unwrap();
        assert!(combined_context.contains(&device_group));
    }

    #[test]
    fn visible_summaries_hide_unauthorized_objects_and_withhold_unreadable_versions() {
        let mut catalog = catalog_with_user();
        let alice = user("alice");
        let bob = user("bob");
        catalog
            .directory
            .add_user(bob.clone(), "Bob".to_string())
            .unwrap();
        let _ = context_for_user(&mut catalog, &alice);
        let key = "test-public-key-alice";
        let blob = |id: &str, name: &str| {
            MeshObject::new(
                object_id(id),
                MeshObjectKind::Blob {
                    media_type: "text/plain".to_string(),
                },
                name.to_string(),
                None,
                bob.clone(),
            )
        };
        let mut readable = blob("readable", "ok.txt");
        readable.acl.add_entry(
            alice.clone(),
            AclEffect::Allow,
            [ObjectPermission::Read],
            false,
        );
        let mut listed = blob("listed", "listed.txt");
        listed.acl.add_entry(
            alice.clone(),
            AclEffect::Allow,
            [ObjectPermission::List],
            false,
        );
        let mut denied = blob("denied", "denied.txt");
        denied.acl.add_entry(
            alice.clone(),
            AclEffect::Allow,
            [ObjectPermission::Read],
            false,
        );
        denied
            .acl
            .add_entry(alice, AclEffect::Deny, [ObjectPermission::Read], false);
        let hidden = blob("hidden", "hidden.txt");
        for object in [readable, listed, denied, hidden] {
            catalog.insert_object(object).unwrap();
        }

        let summaries = catalog
            .visible_summaries_for_authenticated_device(key, 100)
            .unwrap();
        let names: Vec<_> = summaries.iter().map(|s| s.display_name.as_str()).collect();
        assert!(names.contains(&"ok.txt"));
        assert!(names.contains(&"listed.txt"));
        assert!(!names.contains(&"hidden.txt"));
        assert!(
            summaries
                .iter()
                .find(|s| s.display_name == "ok.txt")
                .unwrap()
                .readable
        );
        assert!(
            !summaries
                .iter()
                .find(|s| s.display_name == "listed.txt")
                .unwrap()
                .readable
        );
        assert_eq!(
            catalog
                .visible_summaries_for_authenticated_device(key, 1)
                .unwrap()
                .len(),
            1
        );
        assert!(catalog
            .visible_summaries_for_authenticated_device("unknown-key", 10)
            .is_err());
    }

    #[test]
    fn access_context_is_bound_to_a_registered_device_and_mesh() {
        let mut catalog = catalog_with_user();
        let alice = user("alice");
        let device_id = PrincipalId::device("alice-laptop").unwrap();
        let public_key = "authenticated-key";
        catalog
            .directory
            .add_device(
                device_id,
                "Alice laptop".to_string(),
                public_key.to_string(),
                Some(alice.clone()),
            )
            .unwrap();
        let object_id = object_id("alice-private");
        let mut object = MeshObject::new(
            object_id.clone(),
            MeshObjectKind::Blob {
                media_type: "text/plain".to_string(),
            },
            "private.txt".to_string(),
            None,
            alice.clone(),
        );
        object
            .acl
            .add_entry(alice, AclEffect::Allow, [ObjectPermission::Read], false);
        catalog.insert_object(object).unwrap();

        assert!(catalog
            .access_context_for_authenticated_device("unregistered-key")
            .is_err());
        let context = catalog
            .access_context_for_authenticated_device(public_key)
            .unwrap();
        assert!(catalog
            .check_access(
                &object_id,
                &context,
                &BTreeSet::from([ObjectPermission::Read])
            )
            .unwrap());

        let mut other_mesh = MeshObjectCatalog::new("other-mesh").unwrap();
        other_mesh
            .directory
            .add_user(user("alice"), "Alice".to_string())
            .unwrap();
        other_mesh
            .directory
            .add_device(
                PrincipalId::device("alice-laptop").unwrap(),
                "Alice laptop".to_string(),
                public_key.to_string(),
                Some(user("alice")),
            )
            .unwrap();
        assert!(other_mesh
            .check_access(
                &object_id,
                &context,
                &BTreeSet::from([ObjectPermission::Read])
            )
            .is_err());
    }

    #[test]
    fn device_public_keys_must_be_unique() {
        let mut directory = MeshDirectory::default();
        directory
            .add_device(
                PrincipalId::device("device-a").unwrap(),
                "Device A".to_string(),
                "shared-key".to_string(),
                None,
            )
            .unwrap();
        assert!(directory
            .add_device(
                PrincipalId::device("device-b").unwrap(),
                "Device B".to_string(),
                "shared-key".to_string(),
                None,
            )
            .is_err());
    }

    #[test]
    fn inherited_acl_accumulates_group_allow_and_child_deny_wins() {
        let mut catalog = catalog_with_user();
        let alice = user("alice");
        let readers = group("readers");
        catalog
            .directory
            .add_group(readers.clone(), "Readers".to_string())
            .unwrap();
        catalog
            .directory
            .add_group_member(&readers, alice.clone())
            .unwrap();

        let mut share = MeshObject::new(
            object_id("share"),
            MeshObjectKind::Container(ContainerKind::Share),
            "Shared".to_string(),
            None,
            alice.clone(),
        );
        share
            .acl
            .add_entry(readers, AclEffect::Allow, [ObjectPermission::Read], true);
        catalog.insert_object(share).unwrap();

        let file_id = object_id("report");
        let mut file = MeshObject::new(
            file_id.clone(),
            MeshObjectKind::Blob {
                media_type: "application/pdf".to_string(),
            },
            "report.pdf".to_string(),
            Some(object_id("share")),
            alice.clone(),
        );
        assert!(catalog.insert_object(file.clone()).is_ok());
        let read = BTreeSet::from([ObjectPermission::Read]);
        let context = context_for_user(&mut catalog, &alice);
        assert!(catalog.check_access(&file_id, &context, &read).unwrap());

        file.acl.add_entry(
            alice.clone(),
            AclEffect::Deny,
            [ObjectPermission::Read],
            false,
        );
        catalog.objects.insert(file_id.clone(), file.clone());
        assert!(!catalog.check_access(&file_id, &context, &read).unwrap());

        file.acl.entries.clear();
        file.acl.inherit_from_parent = false;
        catalog.objects.insert(file_id.clone(), file);
        assert!(!catalog.check_access(&file_id, &context, &read).unwrap());
    }

    #[test]
    fn versions_are_immutable_metadata_with_content_hashes() {
        let mut catalog = catalog_with_user();
        let alice = user("alice");
        let id = object_id("image");
        let image = MeshObject::new(
            id.clone(),
            MeshObjectKind::Blob {
                media_type: "image/png".to_string(),
            },
            "photo.png".to_string(),
            None,
            alice.clone(),
        );
        catalog.insert_object(image).unwrap();

        let version = ObjectVersion::from_content(
            ObjectVersionId::new("v1").unwrap(),
            b"image bytes",
            10,
            alice,
            PayloadReference {
                provider: "sb-drive".to_string(),
                locator: "objects/image/v1".to_string(),
            },
        );
        let expected_hash: [u8; 32] = Sha256::digest(b"image bytes").into();
        assert_eq!(version.content_hash, expected_hash);
        assert_eq!(version.size_bytes, 11);
        catalog.add_version(&id, version.clone()).unwrap();
        assert!(catalog.add_version(&id, version).is_err());
        assert_eq!(
            catalog.objects.get(&id).unwrap().current_version,
            Some(ObjectVersionId::new("v1").unwrap())
        );
    }

    #[test]
    fn catalog_serializes_with_an_explicit_schema_version() {
        let catalog = catalog_with_user();
        let encoded = serde_json::to_string(&catalog).unwrap();
        let decoded: MeshObjectCatalog = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, catalog);
        assert_eq!(decoded.schema_version, OBJECT_MODEL_SCHEMA_VERSION);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn access_defaults_to_deny_and_disabled_principals_do_not_resolve() {
        let mut catalog = catalog_with_user();
        let alice = user("alice");
        let id = object_id("private-file");
        let object = MeshObject::new(
            id.clone(),
            MeshObjectKind::Blob {
                media_type: "text/plain".to_string(),
            },
            "private.txt".to_string(),
            None,
            alice.clone(),
        );
        catalog.insert_object(object).unwrap();
        let context = context_for_user(&mut catalog, &alice);
        let read = BTreeSet::from([ObjectPermission::Read]);

        assert!(!catalog.check_access(&id, &context, &read).unwrap());
        catalog.directory.set_enabled(&alice, false).unwrap();
        assert!(catalog.check_access(&id, &context, &read).is_err());
    }

    #[test]
    fn malformed_acl_and_parent_cycles_fail_closed() {
        let mut catalog = catalog_with_user();
        let alice = user("alice");
        let parent_id = object_id("parent");
        let child_id = object_id("child");
        let parent = MeshObject::new(
            parent_id.clone(),
            MeshObjectKind::Container(ContainerKind::Folder),
            "Parent".to_string(),
            None,
            alice.clone(),
        );
        catalog.insert_object(parent).unwrap();
        let child = MeshObject::new(
            child_id.clone(),
            MeshObjectKind::Container(ContainerKind::Folder),
            "Child".to_string(),
            Some(parent_id.clone()),
            alice.clone(),
        );
        catalog.insert_object(child).unwrap();

        catalog.objects.get_mut(&parent_id).unwrap().acl.add_entry(
            group("missing"),
            AclEffect::Allow,
            [ObjectPermission::Read],
            true,
        );
        assert!(catalog.validate().is_err());
        let context = context_for_user(&mut catalog, &alice);
        assert!(catalog
            .check_access(
                &parent_id,
                &context,
                &BTreeSet::from([ObjectPermission::Read]),
            )
            .is_err());

        catalog
            .objects
            .get_mut(&parent_id)
            .unwrap()
            .acl
            .entries
            .clear();
        catalog.objects.get_mut(&parent_id).unwrap().parent_id = Some(child_id.clone());
        assert!(catalog.validate().is_err());
        assert!(catalog
            .check_access(
                &parent_id,
                &context,
                &BTreeSet::from([ObjectPermission::Read]),
            )
            .is_err());
    }

    #[test]
    fn invalid_payload_references_are_rejected_when_adding_versions() {
        let mut catalog = catalog_with_user();
        let alice = user("alice");
        let id = object_id("document");
        catalog
            .insert_object(MeshObject::new(
                id.clone(),
                MeshObjectKind::Blob {
                    media_type: "text/plain".to_string(),
                },
                "document.txt".to_string(),
                None,
                alice.clone(),
            ))
            .unwrap();
        let invalid = ObjectVersion::from_content(
            ObjectVersionId::new("v1").unwrap(),
            b"content",
            1,
            alice,
            PayloadReference {
                provider: "sb-drive".to_string(),
                locator: "  ".to_string(),
            },
        );
        assert!(catalog.add_version(&id, invalid).is_err());
    }
}
