const { buildSchema } = require("graphql");

// create the GraphQL schema
// use backticks to write a multi-line string
module.exports = buildSchema(`

    type AuthData {
        token: String!
        userId: String!
    }

    input UserInputData {
        email: String!
        name: String!
        password: String!
    }

    type Post {
        _id: ID!
        title: String!
        content: String!
        imageUrl: String!
        creator: User!
        createdAt: String!
        updatedAt: String!
    }

    type User {
        _id: ID!
        name: String!
        email: String!
        password: String
        status: String!
        post: [Post!]!
    }

    input PostInputData {
        title: String!
        content: String!
        imageUrl: String!
    }

    type PostPageData {
        posts: [Post!]!
        totalItems: Int!
    }

    type RootQuery {
        login(email: String!, password: String!): AuthData!
        getPosts(page: Int): PostPageData!
        getPost(postId: ID!): Post
        getUser: User!
    }

    type RootMutation {
        signup(userInput: UserInputData!): User!
        createPost(postInput: PostInputData!): Post!
        updatePost(postId: ID!, postInput: PostInputData!): Post!
        deletePost(postId: ID!): Boolean!
        updateUserStatus(status: String!): Boolean!
    }

    schema {
        query: RootQuery
        mutation: RootMutation
    }
`);