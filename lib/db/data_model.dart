part of aqueduct;

/// Container for [ModelEntity]s, representing [Model] objects and their properties.
///
/// Required for [ModelContext].
class DataModel {

  /// Creates an instance of [DataModel] from a list of types that extends [Model].
  ///
  /// To register a class as a model object within this, you must include its type in the list. Example:
  ///
  ///       new DataModel([User, Token, Posts]);
  DataModel(List<Type> modelTypes) {
    _buildEntities(modelTypes);
  }

  DataModel._fromModelBundle(String modelBundlePath) {
    // This will build the model from a series of schema files.
  }

  Map<Type, ModelEntity> _entities = {};
  Map<Type, ModelEntity> _persistentTypeToEntityMap = {};

  /// Returns a [ModelEntity] for a [Type].
  ///
  /// [type] may be either the instance type or persistent instance type. For example, the following model
  /// definition, you could retrieve its entity via MyModel or _MyModel:
  ///
  ///         class MyModel extends Model<_MyModel> implements _MyModel {}
  ///         class _MyModel {
  ///           @primaryKey
  ///           int id;
  ///         }
  ModelEntity entityForType(Type type) {
    return _entities[type] ?? _persistentTypeToEntityMap[type];
  }

  void _buildEntities(List<Type> modelTypes) {
    modelTypes.forEach((type) {
      var entity = new ModelEntity(this, reflectClass(type), _backingMirrorForType(type));
      _entities[type] = entity;
      _persistentTypeToEntityMap[entity.persistentInstanceTypeMirror.reflectedType] = entity;
    });

    _entities.forEach((_, entity) {
      entity._tableName = _tableNameForEntity(entity);
      entity.attributes = _attributeMapForEntity(entity);
      entity._primaryKey = entity.attributes.values.firstWhere((attrDesc) => attrDesc.isPrimaryKey, orElse: () => null)?.name;
      if (entity.primaryKey == null) {
        throw new DataModelException("No primary key for entity ${MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName)}");
      }
    });

    _entities.forEach((_, entity) {
      entity.relationships = _relationshipMapForEntity(entity);
    });
  }

  String _tableNameForEntity(ModelEntity entity) {
    var tableNameSymbol = #tableName;
    if (entity.persistentInstanceTypeMirror.staticMembers[tableNameSymbol] != null) {
      return entity.persistentInstanceTypeMirror
          .invoke(tableNameSymbol, [])
          .reflectee;
    }

    return MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName);
  }

  Map<String, AttributeDescription> _attributeMapForEntity(ModelEntity entity) {
    Map<String, AttributeDescription> map = {};
    entity.persistentInstanceTypeMirror.declarations.forEach((sym, declMir) {
      if (declMir is VariableMirror && !declMir.isStatic) {
        var key = MirrorSystem.getName(sym);
        bool hasRelationship = declMir.metadata.firstWhere((im) => im.type.isSubtypeOf(reflectType(Relationship)), orElse: () => null) != null;
        if (!hasRelationship) {
          map[key] = _attributeFromVariableMirror(entity, declMir);
        }
      }
    });
    return map;
  }

  AttributeDescription _attributeFromVariableMirror(ModelEntity entity, VariableMirror mirror) {
    Attributes metadataAttrs = mirror.metadata
        .firstWhere((im) => im.type.isSubtypeOf(reflectType(Attributes)), orElse: () => null)
        ?.reflectee;

    var type = metadataAttrs?.databaseType ?? PropertyDescription.propertyTypeForDartType(mirror.type.reflectedType);
    if (type == null) {
      throw new DataModelException("Property ${MirrorSystem.getName(mirror.simpleName)} on ${MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName)} has invalid type");
    }

    return new AttributeDescription(entity, MirrorSystem.getName(mirror.simpleName), type,
        primaryKey: metadataAttrs?.isPrimaryKey ?? false,
        defaultValue: metadataAttrs?.defaultValue ?? null,
        unique: metadataAttrs?.isUnique ?? false,
        indexed: metadataAttrs?.isIndexed ?? false,
        nullable: metadataAttrs?.isNullable ?? false,
        includedInDefaultResultSet: !(metadataAttrs?.shouldOmitByDefault ?? false),
        autoincrement: metadataAttrs?.autoincrement ?? false);
  }

  Map<String, RelationshipDescription> _relationshipMapForEntity(ModelEntity entity) {
    Map<String, RelationshipDescription> map = {};

    entity.persistentInstanceTypeMirror.declarations.forEach((sym, declMir) {
      if (declMir is VariableMirror && !declMir.isStatic) {
        var key = MirrorSystem.getName(sym);
        Relationship relationshipAttribute = declMir.metadata
            .firstWhere((im) => im.type.isSubtypeOf(reflectType(Relationship)), orElse: () => null)
            ?.reflectee;

        if (relationshipAttribute != null) {
          map[key] = _relationshipFromVariableMirror(entity, declMir, relationshipAttribute);
        }
      }
    });

    return map;
  }

  RelationshipDescription _relationshipFromVariableMirror(ModelEntity entity, VariableMirror mirror, Relationship relationshipAttribute) {
    if (mirror.metadata.firstWhere((im) => im.type.isSubtypeOf(reflectType(Attributes)), orElse: () => null) != null) {
      throw new DataModelException("Relationship ${MirrorSystem.getName(mirror.simpleName)} on ${MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName)} must not define additional Attributes");
    }

    String inverseKey = relationshipAttribute.inverseKey;
    var destinationEntity = _destinationEntityForVariableMirror(entity, mirror);
    var destinationVariableMirror = destinationEntity.persistentInstanceTypeMirror.declarations[new Symbol(inverseKey)];
    if (destinationVariableMirror == null) {
      throw new DataModelException("Relationship ${MirrorSystem.getName(mirror.simpleName)} on ${MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName)} has no inverse (tried $inverseKey)");
    }

    Relationship inverseRelationshipProperties = destinationVariableMirror.metadata
        .firstWhere((im) => im.type.isSubtypeOf(reflectType(Relationship)), orElse: () => null)
        ?.reflectee;
    if (inverseRelationshipProperties == null) {
      throw new DataModelException("Relationship ${MirrorSystem.getName(mirror.simpleName)} on ${MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName)} inverse ($inverseKey) has no RelationshipAttribute");
    }

    if ((relationshipAttribute.type == inverseRelationshipProperties.type)
    ||  (relationshipAttribute.type != RelationshipType.belongsTo && inverseRelationshipProperties.type != RelationshipType.belongsTo)) {
      throw new DataModelException("Relationship ${MirrorSystem.getName(mirror.simpleName)} on ${MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName)} inverse ($inverseKey) has non-complimentary RelationshipType");
    }

    if (relationshipAttribute.type == RelationshipType.belongsTo
    && relationshipAttribute.deleteRule == RelationshipDeleteRule.nullify
    && relationshipAttribute.isRequired) {
      throw new DataModelException("Relationship ${MirrorSystem.getName(mirror.simpleName)} on ${entity.tableName} set to nullify on delete, but is not nullable");
    }

    var referenceProperty = destinationEntity.attributes[destinationEntity.primaryKey];

    return new RelationshipDescription(entity, MirrorSystem.getName(mirror.simpleName), referenceProperty.type,
        destinationEntity, relationshipAttribute.deleteRule, relationshipAttribute.type, inverseKey,
        unique: inverseRelationshipProperties.type == RelationshipType.hasOne,
        indexed: relationshipAttribute.type == RelationshipType.belongsTo,
        nullable: !relationshipAttribute.isRequired,
        includedInDefaultResultSet: true);
  }

  ModelEntity _destinationEntityForVariableMirror(ModelEntity entity, VariableMirror mirror) {
    var typeMirror = mirror.type;
    if (mirror.type.isSubtypeOf(reflectType(List))) {
      typeMirror = typeMirror.typeArguments.first;
    }

    var destinationEntity = _entities[typeMirror.reflectedType];
    if (destinationEntity == null) {
      throw new DataModelException("Relationship ${MirrorSystem.getName(mirror.simpleName)} on ${MirrorSystem.getName(entity.persistentInstanceTypeMirror.simpleName)} destination ModelEntity does not exist");
    }

    return destinationEntity;
  }

  ClassMirror _backingMirrorForType(Type modelType) {
    var rt = reflectClass(modelType);
    var modelRefl = reflectType(Model);
    var entityTypeRefl = rt;

    while (rt.superclass.isSubtypeOf(modelRefl)) {
      rt = rt.superclass;
      entityTypeRefl = rt;
    }

    if (rt.isSubtypeOf(modelRefl)) {
      entityTypeRefl = entityTypeRefl.typeArguments.first;
    } else {
      throw new DataModelException("Invalid modelType $modelType ${reflectClass(modelType).simpleName}");
    }

    return entityTypeRefl;
  }
}

/// Thrown when a [DataModel] encounters an error.
class DataModelException implements Exception {
  DataModelException(this.message);

  final String message;

  String toString() {
    return "DataModelException: $message";
  }
}