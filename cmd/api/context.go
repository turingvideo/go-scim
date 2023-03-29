package api

import (
	"context"
	"github.com/imulab/go-scim/cmd/internal/groupsync"
	scimmongo "github.com/imulab/go-scim/mongo/v2"
	"github.com/imulab/go-scim/pkg/v2/crud"
	"github.com/imulab/go-scim/pkg/v2/db"
	"github.com/imulab/go-scim/pkg/v2/service"
	"github.com/imulab/go-scim/pkg/v2/service/filter"
	"github.com/imulab/go-scim/pkg/v2/spec"
	"github.com/rs/zerolog"
	"github.com/streadway/amqp"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"sync"
	"time"
)

type ApplicationContext struct {
	args                      *arguments
	logger                    *zerolog.Logger
	serviceProviderConfig     *spec.ServiceProviderConfig
	registerSchemaOnce        sync.Once
	userResourceType          *spec.ResourceType
	groupResourceType         *spec.ResourceType
	userDatabase              db.DB
	groupDatabase             db.DB
	mongoClient               *mongo.Client
	registerMongoMetadataOnce sync.Once
	rabbitMqConn              *amqp.Connection
	rabbitMqChannel           *amqp.Channel
	userCreateService         service.Create
	groupCreateService        service.Create
	userReplaceService        service.Replace
	groupReplaceService       service.Replace
	userPatchService          service.Patch
	groupPatchService         service.Patch
	userDeleteService         service.Delete
	groupDeleteService        service.Delete
	userGetService            service.Get
	groupGetService           service.Get
	userQueryService          service.Query
	groupQueryService         service.Query
}

type ConfigPath struct {
	// Path to the service provider config JSON file
	ServiceProviderConfigPath string
	// Path to the user resource type JSON file
	UserResourceTypePath string
	// Path to the group resource type JSON file
	GroupResourceTypePath string
	// Path to the directory containing all schema JSON file
	SchemasDirectory string
}

func NewApplicationContext(configPath ConfigPath) *ApplicationContext {
	arg := newArgs()
	arg.ServiceProviderConfigPath = configPath.ServiceProviderConfigPath
	arg.UserResourceTypePath = configPath.UserResourceTypePath
	arg.GroupResourceTypePath = configPath.GroupResourceTypePath
	arg.SchemasDirectory = configPath.SchemasDirectory

	app := &ApplicationContext{args: arg}
	app.ensureSchemaRegistered()
	return app
}

func (ctx *ApplicationContext) SetUserDatabase(db db.DB) {
	ctx.userDatabase = db
}

func (ctx *ApplicationContext) SetGroupDatabase(db db.DB) {
	ctx.groupDatabase = db
}

func (ctx *ApplicationContext) Logger() *zerolog.Logger {
	if ctx.logger == nil {
		ctx.logger = ctx.args.Logger()
		ctx.logger.Info().Msg("logger initialized")
	}
	return ctx.logger
}

func (ctx *ApplicationContext) ServiceProviderConfig() *spec.ServiceProviderConfig {
	if ctx.serviceProviderConfig == nil {
		spc, err := ctx.args.ParseServiceProviderConfig()
		if err != nil {
			ctx.logInitFailure("service provider config", err)
			panic(err)
		}
		ctx.serviceProviderConfig = spc
		ctx.logInitialized("service provider config")
	}
	return ctx.serviceProviderConfig
}

func (ctx *ApplicationContext) UserResourceType() *spec.ResourceType {
	ctx.ensureSchemaRegistered()
	if ctx.userResourceType == nil {
		u, err := ctx.args.ParseUserResourceType()
		if err != nil {
			ctx.logInitFailure("user resource type", err)
			panic(err)
		}
		ctx.userResourceType = u
		crud.Register(ctx.userResourceType)
		ctx.logInitialized("user resource type")
	}
	return ctx.userResourceType
}

func (ctx *ApplicationContext) GroupResourceType() *spec.ResourceType {
	ctx.ensureSchemaRegistered()
	if ctx.groupResourceType == nil {
		g, err := ctx.args.ParseGroupResourceType()
		if err != nil {
			ctx.logInitFailure("group resource type", err)
			panic(err)
		}
		ctx.groupResourceType = g
		crud.Register(ctx.groupResourceType)
		ctx.logInitialized("group resource type")
	}
	return ctx.groupResourceType
}

func (ctx *ApplicationContext) ensureSchemaRegistered() {
	ctx.registerSchemaOnce.Do(func() {
		if err := ctx.args.RegisterSchemas(); err != nil {
			ctx.logInitFailure("schema", err)
			panic(err)
		}
		ctx.logInitialized("schema")
	})
}

func (ctx *ApplicationContext) MongoClient() *mongo.Client {
	if ctx.mongoClient == nil {
		connectCtx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelFunc()

		c, err := ctx.args.MongoDB.Connect(connectCtx)
		if err != nil {
			ctx.logInitFailure("mongo client", err)
			panic(err)
		}

		ctx.mongoClient = c
		ctx.logInitialized("mongo client")
	}
	return ctx.mongoClient
}

func (ctx *ApplicationContext) UserDatabase() db.DB {
	if ctx.userDatabase == nil {
		if ctx.args.UseMemoryDB {
			ctx.userDatabase = db.Memory()
			ctx.logInitialized("in-memory user database")
		} else {
			ctx.ensureMongoMetadata()
			resourceType := ctx.UserResourceType()
			collection := ctx.MongoClient().
				Database(ctx.args.MongoDB.Database, options.Database()).
				Collection(resourceType.Name(), options.Collection())
			ctx.userDatabase = scimmongo.DB(resourceType, collection, scimmongo.Options().IgnoreProjection())
			ctx.logInitialized("mongo user database")
		}
	}
	return ctx.userDatabase
}

func (ctx *ApplicationContext) GroupDatabase() db.DB {
	if ctx.groupDatabase == nil {
		if ctx.args.UseMemoryDB {
			ctx.groupDatabase = db.Memory()
			ctx.logInitialized("in-memory group database")
		} else {
			ctx.ensureMongoMetadata()
			resourceType := ctx.GroupResourceType()
			collection := ctx.MongoClient().
				Database(ctx.args.MongoDB.Database, options.Database()).
				Collection(resourceType.Name(), options.Collection())
			ctx.groupDatabase = scimmongo.DB(resourceType, collection, scimmongo.Options().IgnoreProjection())
			ctx.logInitialized("mongo group database")
		}
	}
	return ctx.groupDatabase
}

func (ctx *ApplicationContext) ensureMongoMetadata() {
	ctx.registerMongoMetadataOnce.Do(func() {
		if err := ctx.args.MongoDB.RegisterMetadata(); err != nil {
			ctx.logInitFailure("mongo metadata", err)
			panic(err)
		}
		ctx.logInitialized("mongo metadata")
	})
}

func (ctx *ApplicationContext) UserCreateService() service.Create {
	if ctx.userCreateService == nil {
		ctx.userCreateService = service.CreateService(ctx.UserResourceType(), ctx.UserDatabase(), []filter.ByResource{
			filter.ByPropertyToByResource(
				filter.ReadOnlyFilter(),
				filter.UUIDFilter(),
				filter.BCryptFilter(),
			),
			filter.MetaFilter(),
			filter.ByPropertyToByResource(filter.ValidationFilter(ctx.UserDatabase())),
		})
		ctx.logInitialized("user create service")
	}
	return ctx.userCreateService
}

func (ctx *ApplicationContext) GroupCreateService() service.Create {
	if ctx.groupCreateService == nil {
		ctx.groupCreateService = &groupCreated{
			service: service.CreateService(ctx.GroupResourceType(), ctx.GroupDatabase(), []filter.ByResource{
				filter.ByPropertyToByResource(
					filter.ReadOnlyFilter(),
					filter.UUIDFilter(),
				),
				filter.MetaFilter(),
				filter.ByPropertyToByResource(filter.ValidationFilter(ctx.GroupDatabase())),
			}),
			sender: &groupSyncSender{
				channel: ctx.RabbitMQChannel(),
				logger:  ctx.Logger(),
			},
		}
		ctx.logInitialized("group create service")
	}
	return ctx.groupCreateService
}

func (ctx *ApplicationContext) UserReplaceService() service.Replace {
	if ctx.userReplaceService == nil {
		ctx.userReplaceService = service.ReplaceService(ctx.ServiceProviderConfig(), ctx.UserResourceType(), ctx.UserDatabase(), []filter.ByResource{
			filter.ByPropertyToByResource(
				filter.ReadOnlyFilter(),
				filter.BCryptFilter(),
			),
			filter.ByPropertyToByResource(filter.ValidationFilter(ctx.UserDatabase())),
			filter.MetaFilter(),
		})
		ctx.logInitialized("user replace service")
	}
	return ctx.userReplaceService
}

func (ctx *ApplicationContext) GroupReplaceService() service.Replace {
	if ctx.groupReplaceService == nil {
		ctx.groupReplaceService = &groupReplaced{
			service: service.ReplaceService(ctx.ServiceProviderConfig(), ctx.GroupResourceType(), ctx.GroupDatabase(), []filter.ByResource{
				filter.ByPropertyToByResource(
					filter.ReadOnlyFilter(),
				),
				filter.ByPropertyToByResource(filter.ValidationFilter(ctx.UserDatabase())),
				filter.MetaFilter(),
			}),
			sender: &groupSyncSender{
				channel: ctx.RabbitMQChannel(),
				logger:  ctx.Logger(),
			},
		}
		ctx.logInitialized("group replace service")
	}
	return ctx.groupReplaceService
}

func (ctx *ApplicationContext) UserPatchService() service.Patch {
	if ctx.userPatchService == nil {
		ctx.userPatchService = service.PatchService(ctx.ServiceProviderConfig(), ctx.UserDatabase(), []filter.ByResource{}, []filter.ByResource{
			filter.ByPropertyToByResource(
				filter.ReadOnlyFilter(),
				filter.BCryptFilter(),
			),
			filter.ByPropertyToByResource(filter.ValidationFilter(ctx.UserDatabase())),
			filter.MetaFilter(),
		})
		ctx.logInitialized("user patch service")
	}
	return ctx.userPatchService
}

func (ctx *ApplicationContext) GroupPatchService() service.Patch {
	if ctx.groupPatchService == nil {
		ctx.groupPatchService = &groupPatched{
			service: service.PatchService(ctx.ServiceProviderConfig(), ctx.GroupDatabase(), []filter.ByResource{}, []filter.ByResource{
				filter.ByPropertyToByResource(
					filter.ReadOnlyFilter(),
				),
				filter.ByPropertyToByResource(filter.ValidationFilter(ctx.GroupDatabase())),
				filter.MetaFilter(),
			}),
			sender: &groupSyncSender{
				channel: ctx.RabbitMQChannel(),
				logger:  ctx.Logger(),
			},
		}
		ctx.logInitialized("group patch service")
	}
	return ctx.groupPatchService
}

func (ctx *ApplicationContext) UserDeleteService() service.Delete {
	if ctx.userDeleteService == nil {
		ctx.userDeleteService = service.DeleteService(ctx.ServiceProviderConfig(), ctx.UserDatabase())
		ctx.logInitialized("user delete service")
	}
	return ctx.userDeleteService
}

func (ctx *ApplicationContext) GroupDeleteService() service.Delete {
	if ctx.groupDeleteService == nil {
		ctx.groupDeleteService = &groupDeleted{
			service: service.DeleteService(ctx.ServiceProviderConfig(), ctx.GroupDatabase()),
			sender: &groupSyncSender{
				channel: ctx.RabbitMQChannel(),
				logger:  ctx.Logger(),
			},
		}
		ctx.logInitialized("group delete service")
	}
	return ctx.groupDeleteService
}

func (ctx *ApplicationContext) UserGetService() service.Get {
	if ctx.userGetService == nil {
		ctx.userGetService = service.GetService(ctx.UserDatabase())
		ctx.logInitialized("user get service")
	}
	return ctx.userGetService
}

func (ctx *ApplicationContext) GroupGetService() service.Get {
	if ctx.groupGetService == nil {
		ctx.groupGetService = service.GetService(ctx.GroupDatabase())
		ctx.logInitialized("group get service")
	}
	return ctx.groupGetService
}

func (ctx *ApplicationContext) UserQueryService() service.Query {
	if ctx.userQueryService == nil {
		ctx.userQueryService = service.QueryService(ctx.ServiceProviderConfig(), ctx.UserDatabase())
		ctx.logInitialized("user query service")
	}
	return ctx.userQueryService
}

func (ctx *ApplicationContext) GroupQueryService() service.Query {
	if ctx.groupQueryService == nil {
		ctx.groupQueryService = service.QueryService(ctx.ServiceProviderConfig(), ctx.GroupDatabase())
		ctx.logInitialized("group query service")
	}
	return ctx.groupQueryService
}

func (ctx *ApplicationContext) RabbitMQConnection() *amqp.Connection {
	if ctx.rabbitMqConn == nil {
		connectCtx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelFunc()

		c, err := ctx.args.RabbitMQ.Connect(connectCtx)
		if err != nil {
			ctx.logInitFailure("rabbit connection", err)
			panic(err)
		}
		ctx.rabbitMqConn = c
		ctx.logInitialized("rabbit connection")
	}
	return ctx.rabbitMqConn
}

func (ctx *ApplicationContext) RabbitMQChannel() *amqp.Channel {
	if ctx.rabbitMqChannel == nil {
		c, err := ctx.RabbitMQConnection().Channel()
		if err != nil {
			ctx.logInitFailure("rabbit channel", err)
			panic(err)
		}
		if err := groupsync.DeclareQueue(c); err != nil {
			ctx.logInitFailure("rabbit channel", err)
			panic(err)
		}
		ctx.rabbitMqChannel = c
		ctx.logInitialized("rabbit channel")
	}
	return ctx.rabbitMqChannel
}

func (ctx *ApplicationContext) Close() {
	if ctx.mongoClient != nil {
		_ = ctx.mongoClient.Disconnect(context.Background())
	}
	if ctx.rabbitMqChannel != nil {
		_ = ctx.rabbitMqChannel.Close()
	}
}

func (ctx *ApplicationContext) logInitialized(resourceName string) {
	ctx.Logger().
		Info().
		Fields(map[string]interface{}{
			"component": resourceName,
			"status":    "initialized",
		}).
		Msg("component initialized")
}

func (ctx *ApplicationContext) logInitFailure(resourceName string, err error) {
	ctx.Logger().
		Fatal().
		Err(err).
		Fields(map[string]interface{}{
			"component": resourceName,
			"status":    "initialization_failed",
		}).
		Msg("component failed to initialize")
}
